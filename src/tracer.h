#ifndef TRACER_H
#define TRACER_H

#include "axon.h"

#ifdef ENABLE_TRACER

#include "tls.h"

#include <linux/bpf.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/uio.h>

// TRACER_FD is a reserved FD that is assigned write tracing output. it is
// used to report syscalls as behaviour is intercepted from the workload
// programs and is blocked from dup/close in the seccomp policy
#define TRACER_FD 0x3fe

// enabled_traces is a bitfield containing the enabled trace types
extern uint32_t enabled_traces;
enum trace_types
{
	TRACE_TYPE_EXEC = 1 << 0,
	TRACE_TYPE_OPEN_FOR_MODIFY = 1 << 1,
	TRACE_TYPE_OPEN_READ_ONLY = 1 << 2,
	TRACE_TYPE_EXIT = 1 << 3,
	TRACE_TYPE_CLONE = 1 << 4,
	TRACE_TYPE_UPDATE_CREDENTIALS = 1 << 5,
	TRACE_TYPE_UPDATE_WORKING_DIR = 1 << 6,
	TRACE_TYPE_CREATE = 1 << 7,
	TRACE_TYPE_DELETE = 1 << 8,
	TRACE_TYPE_HARDLINK = 1 << 9,
	TRACE_TYPE_RENAME = 1 << 10,
	TRACE_TYPE_ATTRIBUTE_CHANGE = 1 << 11,
	TRACE_TYPE_SYMLINK = 1 << 12,
	TRACE_TYPE_PTRACE = 1 << 13,
	TRACE_TYPE_CONNECT = 1 << 14,
	TRACE_TYPE_CONNECT_CLOUD = 1 << 15,
	TRACE_TYPE_BPF = 1 << 16,
	TRACE_TYPE_BRK = 1 << 17,
	TRACE_TYPE_IOCTL = 1 << 18,
	TRACE_TYPE_LISTEN = 1 << 19,
	TRACE_TYPE_BIND = 1 << 20,
	TRACE_TYPE_DUP = 1 << 21,
	TRACE_TYPE_RLIMIT = 1 << 22,
	TRACE_TYPE_USER_FAULT = 1 << 23,
	TRACE_TYPE_SETUID = 1 << 24,
	TRACE_TYPE_SETGID = 1 << 25,
	TRACE_TYPE_SENDTO = 1 << 26,
	TRACE_TYPE_CHMOD = 1 << 27,
	TRACE_TYPE_MEMORY_PROTECTION = 1 << 28,
	TRACE_TYPE_ACCEPT = 1 << 29,
	TRACE_TYPE_CONNECT_UNIX = 1 << 30,
};

struct trace_sockaddr
{
	int sa_family;
	union {
		struct
		{
			uint16_t sin_port;
			union {
				uint32_t sin_addr;
				uint8_t sin_addr_array[4];
			};
			uint16_t sin6_port;
			union {
				struct
				{
					uint64_t high;
					uint64_t low;
				} sin6_addr;
				uint8_t sin6_addr_array[16];
			};
		};
		char sun_path[108];
	};
};

// send_exec_event reports an exec
void send_exec_event(struct thread_storage *thread, const char *filename, size_t filename_len, const char *const *argv, int result);
// send_open_for_modify_event reports a file was opened for modification
void send_open_for_modify_event(struct thread_storage *thread, const char *filename, size_t filename_len, int flags, mode_t mode);
// send_open_read_only_event reports a file was opened for reads only
void send_open_read_only_event(struct thread_storage *thread, const char *filename, size_t filename_len, int flags);
// send_exit_event reports a process exited
void send_exit_event(struct thread_storage *thread, int exit_code);
// send_clone_event reports a thread was cloned
void send_clone_event(struct thread_storage *thread, int child_pid, int clone_flags, int result);
// send_update_credentials_event reports that credentials changed
void send_update_credentials_event(struct thread_storage *thread, int uid, int gid);
// send_update_working_dir reports that the working directory changed
void send_update_working_dir_event(struct thread_storage *thread, const char *path, size_t length);
// send_create_event reports a file was created
void send_create_event(struct thread_storage *thread, const char *filename, size_t filename_len, mode_t mode);
// send_delete_event reports a file was deleted
void send_delete_event(struct thread_storage *thread, const char *filename, size_t filename_len);
// send_rename_event reports a file was renamed
void send_rename_event(struct thread_storage *thread, const char *oldname, size_t oldname_len, const char *newname, size_t newname_len);
// send_attribute_change_event reports a file's attributes were changed
void send_attribute_change_event(struct thread_storage *thread, const char *filename, size_t filename_len);
// send_hardlink_event reports a new hardlink was created
void send_hardlink_event(struct thread_storage *thread, const char *source_file, size_t source_file_len, const char *target_file, size_t target_file_len);
// send_symlink_event reports a symlink was created
void send_symlink_event(struct thread_storage *thread, const char *source_file, size_t source_file_len, const char *target_file, size_t target_file_len);
// send_connect_attempt_event reports a connect attempt was made
void send_connect_attempt_event(struct thread_storage *thread, int fd, struct trace_sockaddr addr);
// send_connect_result_event reports a connect completed
void send_connect_result_event(struct thread_storage *thread, int result);
// send_bind_attempt_event reports a bind attempt was made
void send_bind_attempt_event(struct thread_storage *thread, int fd, struct trace_sockaddr addr);
// send_bind_result_event reports a bind completed
void send_bind_result_event(struct thread_storage *thread, int result);
// send_listen_attempt_event reports a listen attempt was made
void send_listen_attempt_event(struct thread_storage *thread, int fd, int backlog);
// send_listen_result_event reports a listen completed
void send_listen_result_event(struct thread_storage *thread, int result);
// send_sendto_attempt_event reports a sendto attempt was made
void send_sendto_attempt_event(struct thread_storage *thread, int fd, struct trace_sockaddr addr);
// send_sendto_result_event reports a sendto completed
void send_sendto_result_event(struct thread_storage *thread, int result);
// send_accept_attempt_event reports an accept attempt was made
void send_accept_attempt_event(struct thread_storage *thread, int sockfd);
// send_accept_result_event reports an accept completed
void send_accept_result_event(struct thread_storage *thread, int result);

// send_ptrace_attempt_event reports a ptrace attempt was made
void send_ptrace_attempt_event(struct thread_storage *thread, int request, pid_t pid, void *addr, void *data);
// send_process_vm_readv_attempt_event reports a process_vm_readv attempt was made
void send_process_vm_readv_attempt_event(struct thread_storage *thread, pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
// send_process_vm_writev_attempt_event reports a process_vm_writev attempt was made
void send_process_vm_writev_attempt_event(struct thread_storage *thread, pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
// send_mm_access_fs_event reports an access attempt was made
void send_mm_access_fs_event(struct thread_storage *thread, pid_t pid, unsigned long mode);
// send_connect_aws_attempt_event reports a connect to the instance metadata IP was attempted
void send_connect_aws_attempt_event(struct thread_storage *thread);
// send_bpf_attempt_event reports a bpf attempt was made
void send_bpf_attempt_event(struct thread_storage *thread, int cmd, union bpf_attr *attr, unsigned int size);
// send_brk_result_event reports a brk call was made
void send_brk_result_event(struct thread_storage *thread, int result);
// send_ioctl_attempt_event reports an ioctl attempt was made
void send_ioctl_attempt_event(struct thread_storage *thread, int fd, unsigned long request, uintptr_t arg3);
// send_dup3_attempt_event reports a dup3 attempt was made
void send_dup3_attempt_event(struct thread_storage *thread, int oldfd, int newfd, int flags);
// send_setrlimit_attempt_event reports a setrlimit attempt was made
void send_setrlimit_attempt_event(struct thread_storage *thread, pid_t pid, int resource, const struct rlimit *rlim);
// send_userfaultfd_attempt_event reports a userfaultfd attempt was made
void send_userfaultfd_attempt_event(struct thread_storage *thread, int flags);
// send_setuid_attempt_event reports a setuid attempt was made
void send_setuid_attempt_event(struct thread_storage *thread, uid_t uid);
// send_seteuid_attempt_event reports a setreuid attempt was made
void send_setreuid_attempt_event(struct thread_storage *thread, uid_t ruid, uid_t euid);
// send_setresuid_attempt_event reports a setresuid attempt was made
void send_setresuid_attempt_event(struct thread_storage *thread, uid_t ruid, uid_t euid, uid_t suid);
// send_setfsuid_attempt_event reports a setfsuid attempt was made
void send_setfsuid_attempt_event(struct thread_storage *thread, uid_t fsuid);
// send_setgid_attempt_event reports a setgid attempt was made
void send_setgid_attempt_event(struct thread_storage *thread, gid_t gid);
// send_setegid_attempt_event reports a setegid attempt was made
void send_setregid_attempt_event(struct thread_storage *thread, gid_t rgid, uid_t egid);
// send_setresgid_attempt_event reports a setresgid attempt was made
void send_setresgid_attempt_event(struct thread_storage *thread, gid_t rgid, gid_t egid, gid_t sgid);
// send_setfsgid_attempt_event reports a setfsgid attempt was made
void send_setfsgid_attempt_event(struct thread_storage *thread, gid_t fsgid);
// send_chmod_event reports a chmod attempt was made
void send_chmod_event(struct thread_storage *thread, const char *filename, size_t filename_len, mode_t mode);
// send_mprotect_attempt_event reports an mprotect call was made
void send_mprotect_attempt_event(struct thread_storage *thread, void *addr, size_t len, int prot);
// send_connect_unix_attempt_event reports a connect to a UNIX domain socket was made
void send_connect_unix_attempt_event(struct thread_storage *thread, const uint64_t *socket_path, size_t addr_len);

// install_tracer sets up the trace FD and starts writing events to standard
// error. This must be called before the seccomp filter is put in place
void install_tracer(uint32_t *enabled_traces, char **envp);

#endif

#endif
