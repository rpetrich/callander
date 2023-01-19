#define _GNU_SOURCE

#include "exec.h"

#include "attempt.h"
#include "axon.h"
#include "handler.h"
#include "fd_table.h"
#include "freestanding.h"
#include "loader.h"
#include "paths.h"
#include "seccomp.h"
#include "telemetry.h"
#include "tls.h"

#include <errno.h>
#include <linux/binfmts.h>
#include <linux/limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

uid_t startup_euid;
gid_t startup_egid;
struct fs_stat axon_stat;

static int pid;

uint32_t enabled_telemetry;

pid_t get_self_pid(void)
{
	int result = atomic_load(&pid);
	if (result == 0) {
		result = fs_getpid();
		atomic_store(&pid, result);
	}
	return (pid_t)result;
}

void invalidate_self_pid(void)
{
	atomic_store(&pid, 0);
}

__attribute__((warn_unused_result))
bool is_axon(const struct fs_stat *stat)
{
	return stat->st_dev == axon_stat.st_dev && stat->st_ino == axon_stat.st_ino;
}

// count_args counts the number of arguments in an argv array
static size_t count_args(const char *const *argv) {
	size_t argc = 0;
	if (argv) {
		while (argv[argc]) {
			argc++;
		}
	}
	return argc;
}

__attribute__((warn_unused_result))
static int exec_fd_script(int fd, const char *named_path, const char *const *argv, const char *const *envp, const char *comm, int depth, size_t header_size, char header[header_size]);
__attribute__((warn_unused_result))
static int exec_fd_elf(int fd, const char *const *argv, const char *const *envp, const char *comm, const char *exec_path);

// exec_fd executes an open file via the axon bootstrap, handling native-arch ELF and #! programs only
int exec_fd(int fd, const char *named_path, const char *const *argv, const char *const *envp, const char *comm, int depth)
{
	// back out the /bin/axon symlink
	char path_buf[PATH_MAX];
	int result = fs_readlink_fd(fd, path_buf, sizeof(path_buf)-1);
	if (result < 0) {
		fs_close(fd);
		return result;
	}
	if (result == sizeof("/bin/axon")-1 && fs_strncmp(path_buf, "/bin/axon", result) == 0) {
		fs_close(fd);
		if (named_path == NULL) {
			return -ENOEXEC;
		}
		size_t len = fs_strlen(named_path);
		fs_memcpy(path_buf, named_path, len);
		fs_memcpy(&path_buf[len], ".axon", sizeof(".axon"));
		fd = fs_open(path_buf, O_RDONLY, 0);
		if (fd < 0) {
			return fd;
		}
	}
	// read the header like the linux kernel does
	char header[BINPRM_BUF_SIZE + 1];
	size_t header_size = fs_pread(fd, header, BINPRM_BUF_SIZE, 0);
	if ((int)header_size < 0) {
		fs_close(fd);
		return -ENOEXEC;
	}
	if (header_size < 4) {
		fs_close(fd);
		return -ENOEXEC;
	}
	if (header[0] == '#' && header[1] == '!') {
		return exec_fd_script(fd, named_path, argv, envp, comm, depth, header_size, header);
	}
	if (header[0] == ELFMAG0 && header[1] == ELFMAG1 && header[2] == ELFMAG2 && header[3] == ELFMAG3) {
		return exec_fd_elf(fd, argv, envp, comm, named_path);
	}
	fs_close(fd);
	return -ENOEXEC;
}

extern const ElfW(Addr) _GLOBAL_OFFSET_TABLE_[] __attribute__((visibility("hidden")));

// exec_fd_elf executes an elf binary from an open file
static int exec_fd_elf(int fd, const char *const *argv, const char *const *envp, const char *comm, const char *exec_path)
{
	// Add the AXON_ADDR and AXON_COMM environment variables
	int envc = count_args(envp);
	struct thread_storage *thread = get_thread_storage();
	const char **new_envp = malloc(sizeof(const char *) * (envc + 5));
	struct attempt_cleanup_state new_envp_cleanup;
	attempt_push_free(thread, &new_envp_cleanup, new_envp);
	size_t exec_path_len = exec_path != NULL ? fs_strlen(exec_path) : 0;
	char *exec_path_buf = malloc(sizeof(AXON_EXEC) + exec_path_len);
	struct attempt_cleanup_state exec_path_buf_cleanup;
	attempt_push_free(thread, &exec_path_buf_cleanup, exec_path_buf);
	memcpy(exec_path_buf, AXON_EXEC, sizeof(AXON_EXEC));
	if (exec_path_len != 0) {
		memcpy(&exec_path_buf[sizeof(AXON_EXEC)-1], exec_path, exec_path_len + 1);
	}
	char addr_buf[64];
	memcpy(addr_buf, AXON_ADDR, sizeof(AXON_ADDR) - 1);
	fs_utoah((uintptr_t)&_DYNAMIC - _GLOBAL_OFFSET_TABLE_[0], &addr_buf[sizeof(AXON_ADDR) - 1]);
	char comm_buf[sizeof(AXON_COMM) + 16];
	memcpy(comm_buf, AXON_COMM, sizeof(AXON_COMM) - 1);
	size_t comm_len;
	if (comm == NULL) {
		comm_len = 0;
	} else {
		// Interpret comm strings as being from the trailing / onwards, if any
		const char *current = comm;
		while (*current) {
			if (*current == '/') {
				comm = current + 1;
			}
			current++;
		}
		comm_len = fs_strlen(comm);
		if (comm_len > 16) {
			comm_len = 16;
		}
		memcpy(&comm_buf[sizeof(AXON_COMM) - 1], comm, comm_len);
	}
	comm_buf[sizeof(AXON_COMM) - 1 + comm_len] = '\0';
#ifdef ENABLE_TELEMETRY
	char tele_buf[64];
	memcpy(tele_buf, AXON_TELE, sizeof(AXON_TELE) - 1);
	fs_utoah(enabled_telemetry, &tele_buf[sizeof(AXON_TELE) - 1]);
#endif
	int j = 0;
	new_envp[j++] = addr_buf;
	new_envp[j++] = comm_buf;
#ifdef ENABLE_TELEMETRY
	new_envp[j++] = tele_buf;
#endif
	new_envp[j++] = exec_path_buf;
	for (int i = 0; i < envc; i++) {
		if (fs_strncmp(envp[i], AXON_ADDR, sizeof(AXON_ADDR) - 1) == 0 ||
			fs_strncmp(envp[i], AXON_COMM, sizeof(AXON_COMM) - 1) == 0 ||
			fs_strncmp(envp[i], AXON_EXEC, sizeof(AXON_EXEC) - 1) == 0)
		{
			fs_close(fd);
			attempt_pop_free(&new_envp_cleanup);
			attempt_pop_free(&exec_path_buf_cleanup);
			return -EINVAL;
		}
#ifdef ENABLE_TELEMETRY
		if (fs_strncmp(envp[i], AXON_TELE, sizeof(AXON_TELE) - 1) != 0) {
			new_envp[j++] = envp[i];
		}
#endif
	}
	new_envp[j] = NULL;
	int result = fs_dup2(fd, MAIN_FD);
	fs_close(fd);
	if (result < 0) {
		attempt_pop_free(&new_envp_cleanup);
		attempt_pop_free(&exec_path_buf_cleanup);
		return result;
	}
	serialize_fd_table_for_exec();
	result = fs_execveat(SELF_FD, empty_string, (char *const*)argv, (char *const*)new_envp, AT_EMPTY_PATH);
	attempt_pop_free(&new_envp_cleanup);
	attempt_pop_free(&exec_path_buf_cleanup);
	return result;
}

// exec_fd_script executes a script from an open file
static int exec_fd_script(int fd, const char *named_path, const char *const *argv, const char *const *envp, const char *comm, int depth, size_t header_size, char header[header_size])
{
	// Script binary format
	if (depth > 4) {
		fs_close(fd);
		return -ELOOP;
	}
	header[header_size] = '\0';
	// Parse #! line
	char *arg0 = &header[2];
	while (*arg0 == ' ' || *arg0 == '\t') {
		arg0++;
	}
	if (*arg0 == '\n' || *arg0 == '\0') {
		fs_close(fd);
		return -ENOEXEC;
	}
	char *arg1 = arg0;
	for (;; arg1++) {
		if (*arg1 == ' ' || *arg1 == '\0') {
			*arg1++ = '\0';
			for (char *terminator = arg1; ; ++terminator) {
				if (*terminator == '\0' || *terminator == '\n') {
					*terminator = '\0';
					break;
				}
			}
			break;
		}
		if (*arg1 == '\n' || *arg1 == '\0') {
			*arg1 = '\0';
			arg1 = NULL;
			break;
		}
	}
	char path_buf[PATH_MAX+1];
	if (named_path == NULL) {
		// Execed via execveat, readlink to get a path to pass to the interpreter
		int link_result = fs_readlink_fd(fd, path_buf, PATH_MAX);
		if (link_result < 0) {
			fs_close(fd);
			return link_result;
		}
		path_buf[link_result] = '\0';
		named_path = path_buf;
	}
	// Recreate arguments to pass to the interpreter script
	size_t argc = count_args(argv);
	const char *new_argv[argc + 3];
	const char **dest_argv = new_argv;
	*dest_argv++ = arg0;
	if (arg1) {
		*dest_argv++ = arg1;
	}
	*dest_argv++ = named_path;
	for (size_t i = 1; i <= argc; i++) {
		*dest_argv++ = argv[i];
	}
	// WRITE_LITERAL(TELEMETRY_FD, "Executing script ");
	// fs_write(TELEMETRY_FD, named_path, fs_strlen(named_path));
	// WRITE_LITERAL(TELEMETRY_FD, " via ");
	// fs_write(TELEMETRY_FD, arg0, fs_strlen(arg0));
	// WRITE_LITERAL(TELEMETRY_FD, "\n");
	int interpreter_fd = fs_open(arg0, O_RDONLY, 0);
	if (interpreter_fd < 0) {
		fs_close(fd);
		return interpreter_fd;
	}
	struct fs_stat interpreter_stat;
	int result = verify_allowed_to_exec(interpreter_fd, &interpreter_stat, startup_euid, startup_egid);
	if (result < 0) {
		fs_close(fd);
		fs_close(interpreter_fd);
		return result;
	}
	result = exec_fd(interpreter_fd, new_argv[0], new_argv, envp, comm, depth + 1);
	fs_close(fd);
	return result;
}

// wrapped_execveat handles exec syscalls
__attribute__((warn_unused_result))
int wrapped_execveat(struct thread_storage *thread, int dfd, const char *filename, const char *const *argv, const char *const *envp, int flags)
{
	// open file to exec
	int fd;
	if (dfd != AT_FDCWD && (flags & AT_EMPTY_PATH) && (filename == NULL || *filename == '\0')) {
		fd = fs_dup(dfd);
	} else {
		fd = fs_openat(dfd, filename, flags & AT_SYMLINK_NOFOLLOW ? O_RDONLY | O_NOFOLLOW : O_RDONLY, 0);
	}
	int result;
	if (fd < 0) {
		result = fd;
		goto error;
	}
	struct attempt_cleanup_state state;
	attempt_push_close(thread, &state, fd);
	// check that we're allowed to exec
	struct fs_stat stat;
	result = verify_allowed_to_exec(fd, &stat, startup_euid, startup_egid);
	if (result != 0) {
		goto close_and_error;
	}
	// if executing axon, change to the main fd and check again
	if (special_path_type(filename) == SPECIAL_PATH_TYPE_EXE && is_axon(&stat)) {
		result = fixup_exe_open(dfd, filename, O_RDONLY);
		if (result < 0) {
			goto close_and_error;
		}
		attempt_pop_close(&state);
		fd = result;
		attempt_push_close(thread, &state, fd);
		result = verify_allowed_to_exec(fd, &stat, startup_euid, startup_egid);
		if (result != 0) {
			goto close_and_error;
		}
	}
#ifdef ENABLE_TELEMETRY
	// send the open read only telemetry event, if necessary
	if (enabled_telemetry & TELEMETRY_TYPE_OPEN_READ_ONLY) {
		char path[PATH_MAX];
		int len = fs_readlink_fd(fd, path, sizeof(path));
		if (len > 0) {
			send_open_read_only_event(thread, path, len, O_RDONLY);
		} else {
			result = -EACCES;
			goto close_and_error;
		}
	}
#endif
	// actually exec
	result = exec_fd(fd, dfd == AT_FDCWD ? filename : NULL, argv, envp, filename, 0);
close_and_error:
	attempt_pop_close(&state);
error:
#ifdef ENABLE_TELEMETRY
	// send the exec event, if failed
	if (enabled_telemetry & TELEMETRY_TYPE_EXEC) {
		send_exec_event(thread, filename, fs_strlen(filename), argv, result);
	}
#endif
	return result;
}

