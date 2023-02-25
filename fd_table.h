#ifndef FD_TABLE_H
#define FD_TABLE_H

#include <stdbool.h>

#define TABLE_FD 0x3fa
#define DEAD_FD 0x3f8
#define CWD_FD 0x3f7

#define HAS_REMOTE_FD 1
#define HAS_LOCAL_FD 2
#define HAS_CLOEXEC 4
#define USED_BITS 3

#define MAX_TABLE_SIZE 1024

void initialize_fd_table(void);
void serialize_fd_table_for_exec(void);
void serialize_fd_table_for_fork(void);
void finish_fd_table_fork(void);
void resurrect_fd_table(void);
void clear_fd_table_for_exit(void);

// install_local_fd takes ownership of local_fd
__attribute__((warn_unused_result))
int install_local_fd(int local_fd, int flags);
// install_remote_fd takes ownership of remote_fd
__attribute__((warn_unused_result))
int install_remote_fd(int remote_fd, int flags);
// become_remote_fd takes ownership of remote_fd
int become_remote_fd(int fd, int remote_fd);
// lookup_real_fd looks up the real file descriptor and returns true if it's remote
__attribute__((warn_unused_result))
bool lookup_real_fd(int fd, int *out_real_fd);

int perform_close(int fd);
__attribute__((warn_unused_result))
int perform_dup(int oldfd, int flags);
__attribute__((warn_unused_result))
int perform_dup3(int oldfd, int newfd, int flags);
int perform_set_fd_flags(int fd, int flags);
__attribute__((warn_unused_result))
int perform_get_fd_flags(int fd);

// chdir_become_remote_fd takes ownership of remote_fd
__attribute__((warn_unused_result))
static inline int chdir_become_remote_fd(int remote_fd)
{
	return become_remote_fd(CWD_FD, remote_fd);
}
__attribute__((warn_unused_result))
int chdir_become_local_path(const char *path);
// chdir_become_local_fd does not take ownership of local_fd
__attribute__((warn_unused_result))
int chdir_become_local_fd(int local_fd);

const int *get_fd_table(void);

#endif
