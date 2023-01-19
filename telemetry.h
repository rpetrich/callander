#ifndef TELEMETRY_H
#define TELEMETRY_H

#ifdef ENABLE_TELEMETRY

#include "tls.h"

#include <linux/bpf.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/uio.h>

// TELMETRY_FD is a reserved FD that is assigned to the sensor process. it is
// used to report telemetry to the sensor as behaviour is intercepted from the
// workload programs and is blocked from dup/close in the seccomp policy
#define TELEMETRY_FD 0x3fe

// enabled_telemetry is a bitfield containing the enabled telemetry
extern uint32_t enabled_telemetry;
enum telemetry_types {
	TELEMETRY_TYPE_EXEC = 1 << 0,
	TELEMETRY_TYPE_OPEN_FOR_MODIFY = 1 << 1,
	TELEMETRY_TYPE_OPEN_READ_ONLY = 1 << 2,
	TELEMETRY_TYPE_EXIT = 1 << 3,
	TELEMETRY_TYPE_CLONE = 1 << 4,
	TELEMETRY_TYPE_UPDATE_CREDENTIALS = 1 << 5,
	TELEMETRY_TYPE_UPDATE_WORKING_DIR = 1 << 6,
	TELEMETRY_TYPE_CREATE = 1 << 7,
	TELEMETRY_TYPE_DELETE = 1 << 8,
	TELEMETRY_TYPE_HARDLINK = 1 << 9,
	TELEMETRY_TYPE_RENAME = 1 << 10,
	TELEMETRY_TYPE_ATTRIBUTE_CHANGE = 1 << 11,
	TELEMETRY_TYPE_SYMLINK = 1 << 12,
	TELEMETRY_TYPE_PTRACE = 1 << 13,
	TELEMETRY_TYPE_CONNECT = 1 << 14,
	TELEMETRY_TYPE_CONNECT_CLOUD = 1 << 15,
	TELEMETRY_TYPE_BPF = 1 << 16,
	TELEMETRY_TYPE_BRK = 1 << 17,
	TELEMETRY_TYPE_IOCTL = 1 << 18,
	TELEMETRY_TYPE_LISTEN = 1 << 19,
	TELEMETRY_TYPE_BIND = 1 << 20,
	TELEMETRY_TYPE_DUP = 1 << 21,
	TELEMETRY_TYPE_RLIMIT = 1 << 22,
	TELEMETRY_TYPE_USER_FAULT = 1 << 23,
	TELEMETRY_TYPE_SETUID = 1 << 24,
	TELEMETRY_TYPE_SETGID = 1 << 25,
	TELEMETRY_TYPE_SENDTO = 1 << 26,
	TELEMETRY_TYPE_CHMOD = 1 << 27,
	TELEMETRY_TYPE_MEMORY_PROTECTION = 1 << 28,
	TELEMETRY_TYPE_ACCEPT = 1 << 29,
	TELEMETRY_TYPE_CONNECT_UNIX = 1 << 30,

	TELEMETRY_TYPE_PRETTY_PRINT = 1 << 31,
};

struct telemetry_sockaddr {
	int sa_family;
	union {
		struct {
			uint16_t sin_port;
			union {
				uint32_t sin_addr;
				uint8_t sin_addr_array[4];
			};
			uint16_t sin6_port;
			union {
				struct {
					uint64_t high;
					uint64_t low;
				} sin6_addr;
				uint8_t sin6_addr_array[16];
			};
		};	
		char sun_path[108];
	};	
};

// send_exec_event sends a TaskExecTelemetryEvent
void send_exec_event(struct thread_storage *thread, const char *filename, size_t filename_len, const char *const *argv, int result);
// send_open_for_modify_event sends a FileOpenForModifyTelemetryEvent
void send_open_for_modify_event(struct thread_storage *thread, const char *filename, size_t filename_len, int flags, mode_t mode);
// send_open_read_only_event sends a FileOpenReadOnlyTelemetryEvent
void send_open_read_only_event(struct thread_storage *thread, const char *filename, size_t filename_len, int flags);
// send_exit_event sends a TaskExitTelemetryEvent
void send_exit_event(struct thread_storage *thread, int exit_code);
// send_clone_event sends a TaskCloneTelemetryEvent
void send_clone_event(struct thread_storage *thread, int child_pid, int clone_flags, int result);
// send_update_credentials_event sends a TaskUpdateCredentialsTelemetryEvent
void send_update_credentials_event(struct thread_storage *thread, int uid, int gid);
// send_update_working_dir sends a TaskUpdateWorkingDirTelemetryEvent
void send_update_working_dir_event(struct thread_storage *thread, const char *path, size_t length);
// send_create_event sends a FileCreateTelemetryEvent
void send_create_event(struct thread_storage *thread, const char *filename, size_t filename_len, mode_t mode);
// send_delete_event sends a FileDeleteTelemetryEvent
void send_delete_event(struct thread_storage *thread, const char *filename, size_t filename_len);
// send_rename_event sends a FileRenameTelemetryEvent
void send_rename_event(struct thread_storage *thread, const char *oldname, size_t oldname_len, const char *newname, size_t newname_len);
// send_attribute_change_event sends a FileAttributeChangeTelemetryEvent
void send_attribute_change_event(struct thread_storage *thread, const char *filename, size_t filename_len);
// send_hardlink_event sends a FileHardLinkTelemetryEvent
void send_hardlink_event(struct thread_storage *thread, const char *source_file, size_t source_file_len, const char *target_file, size_t target_file_len);
// send_symlink_event sends a FileSymLinkTelemetryEvent
void send_symlink_event(struct thread_storage *thread, const char *source_file, size_t source_file_len, const char *target_file, size_t target_file_len);
// send_connect_attempt_event sends a NetworkConnectAttemptTelemetryEvent
void send_connect_attempt_event(struct thread_storage *thread, int fd, struct telemetry_sockaddr addr);
// send_connect_result_event sends a NetworkConnectResultTelemetryEvent
void send_connect_result_event(struct thread_storage *thread, int result);
// send_bind_attempt_event sends a NetworkBindAttemptTelemetryEvent
void send_bind_attempt_event(struct thread_storage *thread, int fd, struct telemetry_sockaddr addr);
// send_bind_result_event sends a NetworkBindResultTelemetryEvent
void send_bind_result_event(struct thread_storage *thread, int result);
// send_listen_attempt_event sends a NetworkListenAttemptTelemetryEvent
void send_listen_attempt_event(struct thread_storage *thread, int fd, int backlog);
// send_listen_result_event sends a NetworkListenResultTelemetryEvent
void send_listen_result_event(struct thread_storage *thread, int result);
// send_sendto_attempt_event sends a NetworkSendtoAttemptTelemetryEvent
void send_sendto_attempt_event(struct thread_storage *thread, int fd, struct telemetry_sockaddr addr);
// send_sendto_result_event sends a NetworkSendtoResultTelemetryEvent
void send_sendto_result_event(struct thread_storage *thread, int result);
// send_accept_attempt_event sends a NetworkAcceptAttemptTelemetryEvent
void send_accept_attempt_event(struct thread_storage *thread, int sockfd);
// send_accept_result_event sends a NetworkAcceptResultTelemetryEvent
void send_accept_result_event(struct thread_storage *thread, int result);

// send_ptrace_attempt_event sends a KernelProbeTelemetryEvent with ptrace arguments filled
void send_ptrace_attempt_event(struct thread_storage *thread, int request, pid_t pid, void *addr, void *data);
// send_process_vm_readv_attempt_event sends a KernelProbeTelemetryEvent with process_vm_readv arguments filled
void send_process_vm_readv_attempt_event(struct thread_storage *thread, pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
// send_process_vm_writev_attempt_event sends a KernelProbeTelemetryEvent with process_vm_writev arguments filled
void send_process_vm_writev_attempt_event(struct thread_storage *thread, pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
// send_mm_access_fs_event sends a KernelProbeTelemetryEvent with mm_access arguments filled
void send_mm_access_fs_event(struct thread_storage *thread, pid_t pid, unsigned long mode);
// send_connect_aws_attempt_event sends a KernelProbeTelemetryEvent with empty arguments filled
void send_connect_aws_attempt_event(struct thread_storage *thread);
// send_bpf_attempt_event sends a KernelProbeTelemetryEvent with bpf arguments filled
void send_bpf_attempt_event(struct thread_storage *thread, int cmd, union bpf_attr *attr, unsigned int size);
// send_brk_result_event sends a TracepointTelemetryEvent with brk result filled
void send_brk_result_event(struct thread_storage *thread, int result);
// send_ioctl_attempt_event sends a KernelProbeTelemetryEvent with ioctl arguments filled
void send_ioctl_attempt_event(struct thread_storage *thread, int fd, unsigned long request, uintptr_t arg3);
// send_dup3_attempt_event sends a KernelProbeTelemetryEvent with dup3 arguments filled
void send_dup3_attempt_event(struct thread_storage *thread, int oldfd, int newfd, int flags);
// send_setrlimit_attempt_event sends a KernelProbeTelemetryEvent with setrlimit arguments filled
void send_setrlimit_attempt_event(struct thread_storage *thread, pid_t pid, int resource, const struct rlimit *rlim);
// send_userfaultfd_attempt_event sends a KernelProbeTelemetryEvent with userfaultfd arguments filled
void send_userfaultfd_attempt_event(struct thread_storage *thread, int flags);
// send_setresuid_attempt_event sends a KernelProbeTelemetryEvent with setuid arguments filled
void send_setuid_attempt_event(struct thread_storage *thread, uid_t uid);
// send_seteuid_attempt_event sends a KernelProbeTelemetryEvent with seteuid arguments filled
void send_setreuid_attempt_event(struct thread_storage *thread, uid_t ruid, uid_t euid);
// send_setresuid_attempt_event sends a KernelProbeTelemetryEvent with setresuid arguments filled
void send_setresuid_attempt_event(struct thread_storage *thread, uid_t ruid, uid_t euid, uid_t suid);
// send_setfsuid_attempt_event sends a KernelProbeTelemetryEvent with setfsuid arguments filled
void send_setfsuid_attempt_event(struct thread_storage *thread, uid_t fsuid);
// send_setresgid_attempt_event sends a KernelProbeTelemetryEvent with setgid arguments filled
void send_setgid_attempt_event(struct thread_storage *thread, gid_t gid);
// send_setegid_attempt_event sends a KernelProbeTelemetryEvent with setegid arguments filled
void send_setregid_attempt_event(struct thread_storage *thread, gid_t rgid, uid_t egid);
// send_setresgid_attempt_event sends a KernelProbeTelemetryEvent with setresgid arguments filled
void send_setresgid_attempt_event(struct thread_storage *thread, gid_t rgid, gid_t egid, gid_t sgid);
// send_setfsgid_attempt_event sends a KernelProbeTelemetryEvent with setfsgid arguments filled
void send_setfsgid_attempt_event(struct thread_storage *thread, gid_t fsgid);
// send_chmod_event sends a KernelProbeTelemetryEvent with chmod arguments filled
void send_chmod_event(struct thread_storage *thread, const char *filename, size_t filename_len, mode_t mode);
// send_mprotect_attempt_event sends a KernelProbeTelemetryEvent with mprotect arguments filled
void send_mprotect_attempt_event(struct thread_storage *thread, void *addr, size_t len, int prot);
// send_connect_unix_attempt_event sends a KernelProbeTelemetryEvent with unix socket connect arguments filled
void send_connect_unix_attempt_event(struct thread_storage *thread, const uint64_t *socket_path, size_t addr_len);

// install_telemetry_client sets up the telemetry FD and starts writing events to
// standard error. This must be called before the seccomp filter is put in place
void install_telemetry_client(uint32_t *enabled_telemetry, char **envp);

#endif

#endif
