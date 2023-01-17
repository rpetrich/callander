#ifndef FD_TABLE_H
#define FD_TABLE_H

#include <stdbool.h>

#define TABLE_FD 0x3fa
#define DEAD_FD 0x3f8
#define CWD_FD 0x3f7

void initialize_fd_table(void);
void serialize_fd_table_for_exec(void);
void serialize_fd_table_for_fork(void);
void finish_fd_table_fork(void);
void resurrect_fd_table(void);
void clear_fd_table(void);

__attribute__((warn_unused_result))
int install_local_fd(int fd, int flags);
__attribute__((warn_unused_result))
int install_remote_fd(int remote_fd, int flags);
int become_remote_fd(int fd, int remote_fd);
// lookup_real_fd looks up the real file descriptor and returns true if it's remote
__attribute__((warn_unused_result))
bool lookup_real_fd(int fd, int *out_fd);

int perform_close(int fd);
__attribute__((warn_unused_result))
int perform_dup(int oldfd, int flags);
__attribute__((warn_unused_result))
int perform_dup3(int oldfd, int newfd, int flags);
int perform_set_fd_flags(int fd, int flags);
__attribute__((warn_unused_result))
int perform_get_fd_flags(int fd);

#endif
