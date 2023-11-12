#define _GNU_SOURCE
#include "tracer.h"

#ifdef ENABLE_TRACER

#define NDEBUG
#include <assert.h>
#include "attempt.h"
#include "exec.h"
#include "freestanding.h"
#include "axon.h"
#include "time.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/un.h>

#define BUF_SIZE 126994
#define EMITTED_SIZE 126894

#define WRITE_LITERAL(fd, lit) fs_write(fd, lit, sizeof(lit)-1)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

void send_exec_event(struct thread_storage *thread, const char *filename, size_t filename_len, const char *const *argv, int result)
{
	WRITE_LITERAL(TRACER_FD, "Traced execve for ");
	fs_write(TRACER_FD, filename, filename_len);
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_open_for_modify_event(struct thread_storage *thread, const char *filename, size_t filename_len, int flags, mode_t mode)
{
	WRITE_LITERAL(TRACER_FD, "Traced open-for-modify for ");
	if (filename != NULL) {
		fs_write(TRACER_FD, filename, filename_len);
	}
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_open_read_only_event(struct thread_storage *thread, const char *filename, size_t filename_len, int flags)
{
	WRITE_LITERAL(TRACER_FD, "Traced open-read-only for ");
	if (filename != NULL) {
		fs_write(TRACER_FD, filename, filename_len);
	}
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_exit_event(struct thread_storage *thread, int exit_code)
{
	WRITE_LITERAL(TRACER_FD, "Traced exit\n");
}

void send_clone_event(struct thread_storage *thread, int child_pid, int clone_flags, int result)
{
	WRITE_LITERAL(TRACER_FD, "Traced clone\n");
}

void send_update_credentials_event(struct thread_storage *thread, int uid, int gid)
{
}

void send_update_working_dir_event(struct thread_storage *thread, const char *path, size_t length)
{
	WRITE_LITERAL(TRACER_FD, "Traced chdir to ");
	fs_write(TRACER_FD, path, length);
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_create_event(struct thread_storage *thread, const char *filename, size_t filename_len, mode_t mode)
{
	WRITE_LITERAL(TRACER_FD, "Traced create for ");
	if (filename != NULL) {
		fs_write(TRACER_FD, filename, filename_len);
	}
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_delete_event(struct thread_storage *thread, const char *filename, size_t filename_len)
{
	WRITE_LITERAL(TRACER_FD, "Traced delete for ");
	if (filename != NULL) {
		fs_write(TRACER_FD, filename, filename_len);
	}
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_rename_event(struct thread_storage *thread, const char *oldname, size_t oldname_len, const char *newname, size_t newname_len)
{
	WRITE_LITERAL(TRACER_FD, "Traced rename from ");
	if (oldname != NULL) {
		fs_write(TRACER_FD, oldname, oldname_len);
	}
	WRITE_LITERAL(TRACER_FD, " for ");
	if (newname != NULL) {
		fs_write(TRACER_FD, newname, newname_len);
	}
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_attribute_change_event(struct thread_storage *thread, const char *filename, size_t filename_len)
{
	WRITE_LITERAL(TRACER_FD, "Traced attribute change for ");
	if (filename != NULL) {
		fs_write(TRACER_FD, filename, filename_len);
	}
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_hardlink_event(struct thread_storage *thread, const char *source_file, size_t source_file_len, const char *target_file, size_t target_file_len)
{
	WRITE_LITERAL(TRACER_FD, "Traced hardlink from ");
	if (source_file != NULL) {
		fs_write(TRACER_FD, source_file, source_file_len);
	}
	WRITE_LITERAL(TRACER_FD, " for ");
	if (target_file != NULL) {
		fs_write(TRACER_FD, target_file, target_file_len);
	}
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_symlink_event(struct thread_storage *thread, const char *source_file, size_t source_file_len, const char *target_file, size_t target_file_len)
{
	WRITE_LITERAL(TRACER_FD, "Traced symlink from ");
	if (source_file != NULL) {
		fs_write(TRACER_FD, source_file, source_file_len);
	}
	WRITE_LITERAL(TRACER_FD, " for ");
	if (target_file != NULL) {
		fs_write(TRACER_FD, target_file, target_file_len);
	}
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_connect_attempt_event(struct thread_storage *thread, int fd, struct tracer_sockaddr addr)
{
	WRITE_LITERAL(TRACER_FD, "Traced connect\n");
}

void send_connect_result_event(struct thread_storage *thread, int result)
{
}

void send_connect_unix_attempt_event(struct thread_storage *thread, const uint64_t *socket_path, size_t addr_len)
{
	WRITE_LITERAL(TRACER_FD, "Traced unix connect\n");
}

void send_bind_attempt_event(struct thread_storage *thread, int fd, struct tracer_sockaddr addr)
{
	WRITE_LITERAL(TRACER_FD, "Traced bind\n");
}

void send_bind_result_event(struct thread_storage *thread, int result)
{
}

void send_listen_attempt_event(struct thread_storage *thread, int fd, int backlog)
{
	WRITE_LITERAL(TRACER_FD, "Traced listen\n");
}

void send_listen_result_event(struct thread_storage *thread, int result)
{
}

void send_sendto_attempt_event(struct thread_storage *thread, int fd, struct tracer_sockaddr addr)
{
	WRITE_LITERAL(TRACER_FD, "Traced sendto\n");
}

void send_sendto_result_event(struct thread_storage *thread, int result)
{
}

void send_accept_attempt_event(struct thread_storage *thread, int sockfd)
{
	WRITE_LITERAL(TRACER_FD, "Traced accept\n");
}

void send_accept_result_event(struct thread_storage *thread, int result)
{
}

void send_ptrace_attempt_event(struct thread_storage *thread, int request, pid_t pid, void *addr, void *data)
{
	WRITE_LITERAL(TRACER_FD, "Traced ptrace\n");
}

void send_process_vm_readv_attempt_event(struct thread_storage *thread, pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)
{
	WRITE_LITERAL(TRACER_FD, "Traced process_vm_readv\n");
}

void send_process_vm_writev_attempt_event(struct thread_storage *thread, pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)
{
	WRITE_LITERAL(TRACER_FD, "Traced process_vm_writev\n");
}

void send_mm_access_fs_event(struct thread_storage *thread, pid_t pid, unsigned long mode)
{
	WRITE_LITERAL(TRACER_FD, "Traced mm_access\n");
}

void send_connect_aws_attempt_event(struct thread_storage *thread)
{
	WRITE_LITERAL(TRACER_FD, "Traced connect_aws\n");
}

void send_bpf_attempt_event(struct thread_storage *thread, int cmd, union bpf_attr *attr, unsigned int size)
{
	WRITE_LITERAL(TRACER_FD, "Traced bpf\n");
}

void send_brk_result_event(struct thread_storage *thread, int result)
{
	WRITE_LITERAL(TRACER_FD, "Traced brk\n");
}

void send_ioctl_attempt_event(struct thread_storage *thread, int fd, unsigned long request, uintptr_t arg3)
{
	WRITE_LITERAL(TRACER_FD, "Traced ioctl\n");
}

void send_dup3_attempt_event(struct thread_storage *thread, int oldfd, int newfd, int flags)
{
	WRITE_LITERAL(TRACER_FD, "Traced dup\n");
}

void send_setrlimit_attempt_event(struct thread_storage *thread, pid_t pid, int resource, const struct rlimit *rlim)
{
	WRITE_LITERAL(TRACER_FD, "Traced setrlimit\n");
}

void send_userfaultfd_attempt_event(struct thread_storage *thread, int flags)
{
	WRITE_LITERAL(TRACER_FD, "Traced userfaultfd\n");
}

void send_setuid_attempt_event(struct thread_storage *thread, uid_t uid)
{
	WRITE_LITERAL(TRACER_FD, "Traced setuid\n");
}

void send_setreuid_attempt_event(struct thread_storage *thread, uid_t ruid, uid_t euid)
{
	WRITE_LITERAL(TRACER_FD, "Traced setreuid\n");
}

void send_setresuid_attempt_event(struct thread_storage *thread, uid_t ruid, uid_t euid, uid_t suid)
{
	WRITE_LITERAL(TRACER_FD, "Traced setresuid\n");
}

void send_setfsuid_attempt_event(struct thread_storage *thread, uid_t fsuid)
{
	WRITE_LITERAL(TRACER_FD, "Traced setfsuid\n");
}

void send_setgid_attempt_event(struct thread_storage *thread, gid_t gid)
{
	WRITE_LITERAL(TRACER_FD, "Traced setgid\n");
}

void send_setregid_attempt_event(struct thread_storage *thread, gid_t rgid, gid_t egid)
{
	WRITE_LITERAL(TRACER_FD, "Traced setregid\n");
}

void send_setresgid_attempt_event(struct thread_storage *thread, gid_t rgid, gid_t egid, gid_t sgid)
{
	WRITE_LITERAL(TRACER_FD, "Traced setresgid\n");
}

void send_setfsgid_attempt_event(struct thread_storage *thread, gid_t fsgid)
{
	WRITE_LITERAL(TRACER_FD, "Traced setfsgid\n");
}

void send_chmod_event(struct thread_storage *thread, const char *filename, size_t filename_len, mode_t mode)
{
	WRITE_LITERAL(TRACER_FD, "Traced chmod for ");
	fs_write(TRACER_FD, filename, filename_len);
	WRITE_LITERAL(TRACER_FD, "\n");
}

void send_mprotect_attempt_event(struct thread_storage *thread, void *addr, size_t len, int prot)
{
	WRITE_LITERAL(TRACER_FD, "Traced mprotect\n");
}

void install_tracer(uint32_t *enabled_traces, char **envp)
{
	// Dup standard error to the tracing output special FD slot
	int result;
	result = fs_dup2(2, TRACER_FD);
	if (UNLIKELY(result < 0)) {
		DIE("unable to assign standard error to axon trace fd", fs_strerror(result));
	}
}

#pragma GCC diagnostic pop

#endif