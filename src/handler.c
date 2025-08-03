#define _GNU_SOURCE
#include "handler.h"

#include "axon.h"
#include "coverage.h"
#include "defaultlibs.h"
#include "exec.h"
#include "fd_table.h"
#include "fork.h"
#include "intercept.h"
#include "loader.h"
#include "paths.h"
#include "proxy.h"
#include "remote.h"
#include "sockets.h"
#include "target.h"
#include "tls.h"
#include "tracer.h"
#include "vfs.h"

#include "callander_print.h"

#include <arpa/inet.h>
#ifdef __x86_64__
#include <asm/prctl.h>
#endif
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/mount.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <termios.h>
#include <utime.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

#ifndef NS_GET_USERNS
#define NSIO 0xb7
#define NS_GET_USERNS _IO(NSIO, 0x1)
#define NS_GET_PARENT _IO(NSIO, 0x2)
#endif

#ifdef ENABLE_TRACER
static void working_dir_changed(struct thread_storage *thread)
{
	if (enabled_traces & TRACE_TYPE_UPDATE_WORKING_DIR) {
		char path[PATH_MAX];
		intptr_t result = fs_getcwd(path, sizeof(path));
		if (result > 0) {
			send_update_working_dir_event(thread, path, result - 1);
		}
	}
}

static bool decode_sockaddr(struct trace_sockaddr *out, const union copied_sockaddr *data, size_t size)
{
	switch ((out->sa_family = data->addr.sa_family)) {
		case AF_INET: {
			out->sin_port = data->in.sin_port;
			out->sin_addr = data->in.sin_addr.s_addr;
			out->sin6_port = 0;
			out->sin6_addr.high = 0;
			out->sin6_addr.low = 0;
			return true;
		}
		case AF_INET6: {
			out->sin_port = 0;
			out->sin_addr = 0;
			out->sin6_port = data->in6.sin6_port;
			const uint64_t *sin6_addr = (const uint64_t *)&data->in6.sin6_addr;
			out->sin6_addr.high = sin6_addr[0];
			out->sin6_addr.low = sin6_addr[1];
			return true;
		}
		case AF_UNIX: {
			memcpy(&out->sun_path, &data->un.sun_path, size - (sizeof(sa_family_t)));
			return true;
		}
		default: {
			return false;
		}
	}
}
#endif

static void unmap_and_exit_thread(void *arg1, void *arg2)
{
	atomic_intptr_t *thread_id = clear_thread_storage();
	fs_munmap(arg1, (size_t)arg2);
	atomic_store_explicit(thread_id, 0, memory_order_release);
	if (fs_gettid() == get_self_pid()) {
		clear_fd_table_for_exit(0);
	}
	fs_exitthread(0);
	__builtin_unreachable();
}

typedef unsigned int tcflag_t;
typedef unsigned char cc_t;

__attribute__((noinline)) static intptr_t invalid_local_remote_mixed_operation(void)
{
	return -EINVAL;
}

__attribute__((noinline)) static intptr_t invalid_local_operation(void)
{
	return -EINVAL;
}

// handle_syscall handles a trapped syscall, potentially emulating or blocking as necessary
intptr_t handle_syscall(struct thread_storage *thread, intptr_t syscall, intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6, ucontext_t *context)
{
#if 0
	ERROR("syscall: ", temp_str(copy_raw_syscall_description(syscall, arg1, arg2, arg3, arg4, arg5, arg6)));
	ERROR_FLUSH();
#endif
	switch (syscall) {
#ifdef __NR_arch_prctl
		case LINUX_SYS_arch_prctl: {
			switch (arg1) {
#if defined(__x86_64__)
				case ARCH_SET_FS: {
					int result = FS_SYSCALL(syscall, arg1, arg2);
					became_multithreaded();
					return result;
				}
#endif
			}
			break;
		}
#endif
		case LINUX_SYS_set_tid_address: {
			set_tid_address((const void *)arg1);
			break;
		}
#ifdef __NR_creat
		case LINUX_SYS_creat: {
			struct vfs_resolved_file file;
			return vfs_install_file(vfs_call(openat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), O_CREAT | O_WRONLY | O_TRUNC, arg2, &file), &file, 0);
		}
#endif
#ifdef __NR_open
		case LINUX_SYS_open: {
			struct vfs_resolved_file file;
			return vfs_install_file(vfs_call(openat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), arg2, arg3, &file), &file, arg2);
		}
#endif
		case LINUX_SYS_openat: {
			struct vfs_resolved_file file;
			return vfs_install_file(vfs_call(openat, vfs_resolve_path(arg1, (const char *)arg2), arg3, arg4, &file), &file, arg3);
		}
#ifdef __NR_openat2
		case LINUX_SYS_openat2: {
			// TODO: handle openat2
			return -ENOSYS;
		}
#endif
		case LINUX_SYS_close: {
			return perform_close(arg1);
		}
		case LINUX_SYS_close_range: {
			return -ENOSYS;
		}
		case LINUX_SYS_execve: {
			const char *path = (const char *)arg1;
			const char *const *argv = (const char *const *)arg2;
			const char *const *envp = (const char *const *)arg3;
			return wrapped_execveat(thread, AT_FDCWD, path, argv, envp, 0);
		}
		case LINUX_SYS_execveat: {
			int dirfd = arg1;
			if (dirfd != AT_FDCWD) {
				return -ENOEXEC;
			}
			const char *path = (const char *)arg2;
			const char *const *argv = (const char *const *)arg3;
			const char *const *envp = (const char *const *)arg4;
			int flags = arg5;
			return wrapped_execveat(thread, dirfd, path, argv, envp, flags);
		}
#ifdef __NR_stat
		case LINUX_SYS_stat: {
			return vfs_call(newfstatat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), (struct fs_stat *)arg2, 0);
		}
#endif
		case LINUX_SYS_fstat: {
			return vfs_call(fstat, vfs_resolve_file(arg1), (struct fs_stat *)arg2);
		}
#ifdef __NR_lstat
		case LINUX_SYS_lstat: {
			return vfs_call(newfstatat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), (struct fs_stat *)arg2, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT);
		}
#endif
		case LINUX_SYS_newfstatat: {
			return vfs_call(newfstatat, vfs_resolve_path(arg1, (const char *)arg2), (struct fs_stat *)arg3, arg4);
		}
		case LINUX_SYS_statx: {
			return vfs_call(statx, vfs_resolve_path(arg1, (const char *)arg2), arg3, arg4, (struct linux_statx *)arg5);
		}
#ifdef __NR_poll
		case LINUX_SYS_poll:
#endif
		case LINUX_SYS_ppoll: {
			struct pollfd *fds = (struct pollfd *)arg1;
			nfds_t nfds = arg2;
			if (nfds == 0) {
				return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4);
			}
			struct attempt_cleanup_state state;
			struct vfs_poll_resolved_file *polls = malloc(sizeof(struct vfs_poll_resolved_file) * nfds);
			attempt_push_free(thread, &state, polls);
			for (nfds_t i = 0; i < nfds; i++) {
				polls[i].file = vfs_resolve_file(fds[i].fd);
				if (i != 0 && polls[i].file.ops != polls[i - 1].file.ops) {
					// cannot poll on both local and remote file descriptors
					attempt_pop_free(&state);
					return invalid_local_remote_mixed_operation();
				}
				polls[i].events = fds[i].events;
				polls[i].revents = fds[i].revents;
			}
			intptr_t result = polls[0].file.ops->ppoll(thread, polls, nfds, syscall == LINUX_SYS_ppoll ? (struct timespec *)arg3 : NULL, syscall == LINUX_SYS_ppoll ? (const sigset_t *)arg4 : NULL);
			if (result >= 0) {
				for (nfds_t i = 0; i < nfds; i++) {
					fds[i].revents = polls[i].revents;
				}
			}
			attempt_pop_free(&state);
			return result;
		}
		case LINUX_SYS_lseek: {
			return vfs_call(lseek, vfs_resolve_file(arg1), arg2, arg3);
		}
		case LINUX_SYS_mmap: {
			// TODO: need to update seccomp policy to trap to userspace
			if ((arg4 & MAP_ANONYMOUS) == 0) {
				return vfs_call(mmap, vfs_resolve_file(arg5), (void *)arg1, arg2, arg3, arg4, arg6);
			}
			return FS_SYSCALL(__NR_mmap, arg1, arg2, arg3, arg4, -1, arg6);
		}
		case LINUX_SYS_pread64: {
			return vfs_call(pread, vfs_resolve_file(arg1), (char *)arg2, arg3, arg4);
		}
		case LINUX_SYS_pwrite64: {
			return vfs_call(pwrite, vfs_resolve_file(arg1), (const char *)arg2, arg3, arg4);
		}
#ifdef __NR_access
		case LINUX_SYS_access: {
			return vfs_call(faccessat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), arg2, 0);
		}
#endif
		case LINUX_SYS_faccessat: {
			return vfs_call(faccessat, vfs_resolve_path(arg1, (const char *)arg2), arg3, 0);
		}
		case LINUX_SYS_faccessat2: {
			return vfs_call(faccessat, vfs_resolve_path(arg1, (const char *)arg2), arg3, arg4);
		}
#ifdef __NR_pipe
		case LINUX_SYS_pipe: {
			int result = FS_SYSCALL(syscall, arg1);
			if (arg1 != 0 && result == 0) {
				int *fds = (int *)arg1;
				fds[0] = install_local_fd(fds[0], 0);
				fds[1] = install_local_fd(fds[1], 0);
			}
			return result;
		}
#endif
#ifdef __NR_chmod
		case LINUX_SYS_chmod: {
			return vfs_call(fchmodat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), arg2, 0);
		}
#endif
#ifdef __NR_pipe2
		case LINUX_SYS_pipe2: {
			int result = FS_SYSCALL(syscall, arg1, arg2);
			if (arg1 != 0 && result == 0) {
				int *fds = (int *)arg1;
				fds[0] = install_local_fd(fds[0], arg2);
				fds[1] = install_local_fd(fds[1], arg2);
			}
			return result;
		}
#endif
		case LINUX_SYS_fchmod: {
			return vfs_call(fchmod, vfs_resolve_file(arg1), arg2);
		}
#ifdef __NR_chown
		case LINUX_SYS_chown: {
			return vfs_call(fchownat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), arg2, arg3, 0);
		}
#endif
		case LINUX_SYS_fchown: {
			return vfs_call(fchown, vfs_resolve_file(arg1), arg2, arg3);
		}
#ifdef __NR_lchown
		case LINUX_SYS_lchown: {
			return vfs_call(fchownat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), arg2, arg3, AT_SYMLINK_NOFOLLOW);
		}
#endif
		case LINUX_SYS_fchownat: {
			return vfs_call(fchownat, vfs_resolve_path(arg1, (const char *)arg2), arg3, arg4, arg5);
		}
#ifdef __NR_select
		case LINUX_SYS_select:
#endif
		case LINUX_SYS_pselect6: {
			int n = arg1;
			fd_set *readfds = (fd_set *)arg2;
			fd_set *writefds = (fd_set *)arg3;
			fd_set *exceptfds = (fd_set *)arg4;
			// translate select to the equivalent poll syscall and possibly send remotely
			struct attempt_cleanup_state state;
			struct pollfd *real_fds = malloc(sizeof(struct pollfd) * n);
			attempt_push_free(thread, &state, real_fds);
			bool has_local = false;
			bool has_remote = false;
			bool fds_all_match = true;
			int nfds = 0;
			for (int i = 0; i < n; i++) {
				if ((readfds != NULL && FD_ISSET(i, readfds)) || (writefds != NULL && FD_ISSET(i, writefds)) || (exceptfds != NULL && FD_ISSET(i, exceptfds))) {
					intptr_t real_fd;
					bool is_remote = lookup_real_fd(i, &real_fd);
					real_fds[nfds].fd = real_fd;
					if (is_remote) {
						if (has_local) {
							// cannot poll on both local and remote file descriptors
							attempt_pop_free(&state);
							return invalid_local_remote_mixed_operation();
						}
						has_remote = true;
					} else {
						if (has_remote) {
							// cannot poll on both local and remote file descriptors
							attempt_pop_free(&state);
							return invalid_local_remote_mixed_operation();
						}
						has_local = true;
					}
					if (real_fds[nfds].fd != i) {
						fds_all_match = false;
					}
					real_fds[nfds].events = ((readfds != NULL && FD_ISSET(i, readfds)) ? (POLLIN | POLLPRI) : 0) | ((writefds != NULL && FD_ISSET(i, writefds)) ? (POLLOUT | POLLWRBAND) : 0);
					// TODO: what about exceptfds?
					nfds++;
				}
			}
			// translate timeout
			struct timespec *timeout;
			struct timespec timeout_copy;
			if (syscall == LINUX_SYS_pselect6) {
				timeout = (struct timespec *)arg5;
			} else if (arg5 != 0) {
				TIMEVAL_TO_TIMESPEC((struct timeval *)arg5, &timeout_copy);
				timeout = &timeout_copy;
			} else {
				timeout = NULL;
			}
			// translate sigset
			const void *sigset = NULL;
			size_t sigsetsize = 0;
			if (syscall == LINUX_SYS_pselect6 && arg6 != 0) {
				struct
				{
					const void *ss;
					size_t ss_len;
				} *sigsetdata = (void *)arg6;
				sigset = sigsetdata->ss;
				sigsetsize = sigsetdata->ss_len;
			}
			int result;
			if (has_remote) {
				// TODO: mask signals for pselect6
				result = remote_ppoll(&real_fds[0], nfds, timeout);
			} else if (fds_all_match) {
				attempt_pop_free(&state);
				// all the file descriptors match, just use the standard LINUX_SYS_select or LINUX_SYS_pselect6
				// syscall that would have been invoked anyway
				return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
			} else {
				result = FS_SYSCALL(LINUX_SYS_ppoll, (intptr_t)&real_fds[0], nfds, (intptr_t)timeout, (intptr_t)sigset, sigsetsize);
			}
			if (result > 0) {
				nfds = 0;
				for (int i = 0; i < n; i++) {
					if ((readfds != NULL && FD_ISSET(i, readfds)) || (writefds != NULL && FD_ISSET(i, writefds)) || (exceptfds != NULL && FD_ISSET(i, exceptfds))) {
						short revents = real_fds[nfds].revents;
						if ((revents & (POLLIN | POLLPRI)) == 0 && readfds != NULL) {
							FD_CLR(i, readfds);
						}
						if ((revents & (POLLOUT | POLLWRBAND)) == 0 && writefds != NULL) {
							FD_CLR(i, writefds);
						}
						if ((revents & (POLLERR | POLLHUP | POLLNVAL)) == 0 && exceptfds != NULL) {
							FD_CLR(i, exceptfds);
						}
						nfds++;
					}
				}
			}
			attempt_pop_free(&state);
			return result;
		}
		case LINUX_SYS_sendfile: {
			return vfs_call(sendfile, vfs_resolve_file(arg1), vfs_resolve_file(arg2), (off_t *)arg3, arg4);
		}
		case LINUX_SYS_recvfrom: {
			return vfs_call(recvfrom, vfs_resolve_file(arg1), (char *)arg2, arg3, arg4, (struct sockaddr *)arg5, (socklen_t *)arg6);
		}
		case LINUX_SYS_sendmsg: {
			return vfs_call(sendmsg, vfs_resolve_file(arg1), (const struct msghdr *)arg2, arg3);
		}
		case LINUX_SYS_recvmsg: {
			return vfs_call(recvmsg, vfs_resolve_file(arg1), (struct msghdr *)arg2, arg3);
		}
		case LINUX_SYS_shutdown: {
			return vfs_call(shutdown, vfs_resolve_file(arg1), arg2);
		}
		case LINUX_SYS_getsockname: {
			return vfs_call(getsockname, vfs_resolve_file(arg1), (struct sockaddr *)arg2, (socklen_t *)arg3);
		}
		case LINUX_SYS_getpeername: {
			return vfs_call(getpeername, vfs_resolve_file(arg1), (struct sockaddr *)arg2, (socklen_t *)arg3);
		}
		case LINUX_SYS_getsockopt: {
			return vfs_call(getsockopt, vfs_resolve_file(arg1), arg2, arg3, (void *)arg4, (socklen_t *)arg5);
		}
		case LINUX_SYS_setsockopt: {
			return vfs_call(setsockopt, vfs_resolve_file(arg1), arg2, arg3, (const void *)arg4, arg5);
		}
		case LINUX_SYS_flock: {
			return vfs_call(flock, vfs_resolve_file(arg1), arg2);
		}
		case LINUX_SYS_fsync: {
			return vfs_call(fsync, vfs_resolve_file(arg1));
		}
		case LINUX_SYS_fdatasync: {
			return vfs_call(fdatasync, vfs_resolve_file(arg1));
		}
		case LINUX_SYS_truncate: {
			return vfs_call(truncate, vfs_resolve_path(AT_FDCWD, (const char *)arg1), arg2);
		}
		case LINUX_SYS_ftruncate: {
			return vfs_call(ftruncate, vfs_resolve_file(arg1), arg2);
		}
#ifdef __NR_getdents
		case LINUX_SYS_getdents: {
			return vfs_call(getdents, vfs_resolve_file(arg1), (void *)arg2, arg3);
		}
#endif
		case LINUX_SYS_statfs: {
			return vfs_call(statfs, vfs_resolve_path(AT_FDCWD, (const char *)arg1), (struct fs_statfs *)arg2);
		}
		case LINUX_SYS_fstatfs: {
			return vfs_call(fstatfs, vfs_resolve_file(arg1), (struct fs_statfs *)arg2);
		}
		case LINUX_SYS_readahead: {
			return vfs_call(readahead, vfs_resolve_file(arg2), arg3, arg4);
		}
		case LINUX_SYS_setxattr:
		case LINUX_SYS_lsetxattr: {
			return vfs_call(setxattr, vfs_resolve_path(AT_FDCWD, (const char *)arg1), (const void *)arg2, (const void *)arg3, arg4, syscall == LINUX_SYS_lsetxattr ? AT_SYMLINK_NOFOLLOW : 0);
		}
		case LINUX_SYS_fsetxattr: {
			return vfs_call(fsetxattr, vfs_resolve_file(arg1), (const void *)arg2, (const void *)arg3, arg4, arg5);
		}
		case LINUX_SYS_getxattr:
		case LINUX_SYS_lgetxattr: {
			return vfs_call(getxattr, vfs_resolve_path(AT_FDCWD, (const char *)arg1), (const void *)arg2, (void *)arg3, arg4, syscall == LINUX_SYS_lgetxattr ? AT_SYMLINK_NOFOLLOW : 0);
		}
		case LINUX_SYS_fgetxattr: {
			return vfs_call(fgetxattr, vfs_resolve_file(arg1), (const void *)arg2, (void *)arg3, arg4);
		}
		case LINUX_SYS_listxattr:
		case LINUX_SYS_llistxattr: {
			return vfs_call(listxattr, vfs_resolve_path(AT_FDCWD, (const char *)arg1), (void *)arg2, arg3, syscall == LINUX_SYS_llistxattr ? AT_SYMLINK_NOFOLLOW : 0);
		}
		case LINUX_SYS_flistxattr: {
			return vfs_call(flistxattr, vfs_resolve_file(arg1), (void *)arg2, arg3);
		}
		case LINUX_SYS_removexattr:
		case LINUX_SYS_lremovexattr: {
			return vfs_call(removexattr, vfs_resolve_path(AT_FDCWD, (const char *)arg1), (const void *)arg2, syscall == LINUX_SYS_lremovexattr ? AT_SYMLINK_NOFOLLOW : 0);
		}
		case LINUX_SYS_fremovexattr: {
			return vfs_call(fremovexattr, vfs_resolve_file(arg1), (const void *)arg2);
		}
		case LINUX_SYS_getdents64: {
			return vfs_call(getdents64, vfs_resolve_file(arg1), (char *)arg2, arg3);
		}
		case LINUX_SYS_fadvise64: {
			return vfs_call(fadvise64, vfs_resolve_file(arg1), arg2, arg3, arg4);
		}
#ifdef __NR_epoll_wait
		case LINUX_SYS_epoll_wait:
#endif
		case LINUX_SYS_epoll_pwait: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			struct epoll_event *events = (struct epoll_event *)arg2;
			int maxevents = arg3;
			int timeout = arg4;
			if (vfs_is_remote_file(&file)) {
				// TODO: support pwait properly when remote
				// TODO: support on aarch64
#ifdef __NR_epoll_wait
				return PROXY_LINUX_CALL(LINUX_SYS_epoll_wait, proxy_value(file.handle), proxy_out(events, sizeof(struct epoll_event) * maxevents), proxy_value(maxevents), proxy_value(timeout));
#else
				return -ENOSYS;
#endif
			}
			return FS_SYSCALL(syscall, file.handle, (intptr_t)events, maxevents, timeout, arg5);
		}
		case LINUX_SYS_epoll_pwait2: {
			return -ENOSYS;
		}
		case LINUX_SYS_epoll_ctl: {
			// TODO: handle epoll_ctl with mixed remote and local fds
			int op = arg2;
			struct epoll_event *event = (struct epoll_event *)arg4;
			struct vfs_resolved_file ep_file = vfs_resolve_file(arg1);
			struct vfs_resolved_file file = vfs_resolve_file(arg3);
			if (vfs_is_remote_file(&file)) {
				if (!vfs_is_remote_file(&ep_file)) {
					intptr_t new_epfd = PROXY_LINUX_CALL(LINUX_SYS_epoll_create1 | PROXY_NO_WORKER, proxy_value(EPOLL_CLOEXEC));
					if (new_epfd < 0) {
						return new_epfd;
					}
					int result = become_remote_fd(arg1, new_epfd);
					if (result < 0) {
						remote_close(new_epfd);
						return result;
					}
					// TODO: find a better way to transition between local and remote
					ep_file.ops = &local_path_ops.dirfd_ops;
					ep_file.handle = new_epfd;
				}
				return PROXY_LINUX_CALL(LINUX_SYS_epoll_ctl, proxy_value(ep_file.handle), proxy_value(op), proxy_value(file.handle), proxy_in(event, sizeof(*event)));
			}
			if (vfs_is_remote_file(&ep_file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, ep_file.handle, arg2, file.handle, arg4);
		}
		case LINUX_SYS_mq_open: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2, arg3, arg4), arg2);
		}
		case LINUX_SYS_mq_timedsend: {
			// TODO: handle mq_timedsend
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4, arg5);
		}
		case LINUX_SYS_mq_timedreceive: {
			// TODO: handle mq_timedreceive
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4, arg5);
		}
		case LINUX_SYS_mq_notify: {
			// TODO: handle mq_notify
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg1, arg2);
		}
		case LINUX_SYS_mq_getsetattr: {
			// TODO: handle mq_getsetattr
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg1, arg2, arg3);
		}
#ifdef __NR_inotify_init
		case LINUX_SYS_inotify_init: {
			return install_local_fd(FS_SYSCALL(syscall), 0);
		}
#endif
		case LINUX_SYS_inotify_init1: {
			return install_local_fd(FS_SYSCALL(syscall, arg1), arg1);
		}
		case LINUX_SYS_inotify_add_watch: {
			// TODO: handle inotify_add_watch
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			struct vfs_resolved_path path = vfs_resolve_path(AT_FDCWD, (const char *)arg2);
			if (vfs_is_remote_file(&file) != vfs_is_remote_path(&path)) {
				return invalid_local_remote_mixed_operation();
			}
			if (path.info.handle != AT_FDCWD) {
				return vfs_is_remote_path(&path) ? invalid_remote_operation() : invalid_local_operation();
			}
			if (vfs_is_remote_file(&file)) {
				return PROXY_LINUX_CALL(LINUX_SYS_inotify_add_watch, proxy_value(file.handle), proxy_string(path.info.path), proxy_value(arg3));
			}
			return FS_SYSCALL(syscall, file.handle, (intptr_t)path.info.path, arg3);
		}
		case LINUX_SYS_inotify_rm_watch: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return PROXY_LINUX_CALL(LINUX_SYS_inotify_rm_watch, file.handle, arg2);
			}
			return FS_SYSCALL(syscall, file.handle, arg2);
		}
		case LINUX_SYS_splice: {
			return vfs_call(splice, vfs_resolve_file(arg1), (off_t *)arg2, vfs_resolve_file(arg3), (off_t *)arg4, arg5, arg6);
		}
		case LINUX_SYS_tee: {
			return vfs_call(tee, vfs_resolve_file(arg1), vfs_resolve_file(arg2), arg3, arg4);
		}
		case LINUX_SYS_sync_file_range: {
			return vfs_call(sync_file_range, vfs_resolve_file(arg1), arg2, arg3, arg4);
		}
		case LINUX_SYS_vmsplice: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4);
		}
#ifdef __NR_utime
		case LINUX_SYS_utime: {
			const struct utimbuf *buf = (const struct utimbuf *)arg2;
			if (buf == NULL) {
				return vfs_call(utimensat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), NULL, 0);
			}
			struct timespec copy[2];
			copy[0].tv_sec = buf->actime;
			copy[0].tv_nsec = 0;
			copy[1].tv_sec = buf->modtime;
			copy[1].tv_nsec = 0;
			return vfs_call(utimensat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), copy, 0);
		}
#endif
		case LINUX_SYS_utimensat: {
			return vfs_call(utimensat, vfs_resolve_path(arg1, (const char *)arg2), (struct timespec *)arg3, arg4);
		}
#ifdef __NR_futimesat
		case LINUX_SYS_futimesat: {
			return vfs_call(utimensat, vfs_resolve_path(arg1, (const char *)arg2), (struct timespec *)arg3, 0);
		}
#endif
#ifdef __NR_signalfd
		case LINUX_SYS_signalfd: {
			int fd = arg1;
			intptr_t real_fd;
			if (fd == -1) {
				real_fd = -1;
			} else {
				struct vfs_resolved_file file = vfs_resolve_file(fd);
				if (vfs_is_remote_file(&file)) {
					return invalid_remote_operation();
				}
				real_fd = file.handle;
			}
			int result = FS_SYSCALL(syscall, real_fd, arg2, arg3);
			if (fd == -1) {
				result = install_local_fd(result, 0);
			}
			return result;
		}
#endif
		case LINUX_SYS_signalfd4: {
			int fd = arg1;
			intptr_t real_fd;
			if (fd == -1) {
				real_fd = -1;
			} else {
				struct vfs_resolved_file file = vfs_resolve_file(arg1);
				if (vfs_is_remote_file(&file)) {
					return invalid_remote_operation();
				}
				real_fd = file.handle;
			}
			int result = FS_SYSCALL(syscall, real_fd, arg2, arg3, arg4);
			if (fd == -1) {
				result = install_local_fd(result, arg4);
			}
			return result;
		}
		case LINUX_SYS_timerfd_create: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), arg2);
		}
#ifdef __NR_eventfd
		case LINUX_SYS_eventfd: {
			return install_local_fd(FS_SYSCALL(syscall, arg1), 0);
		}
#endif
		case LINUX_SYS_eventfd2: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), arg2);
		}
		case LINUX_SYS_fallocate: {
			return vfs_call(fallocate, vfs_resolve_file(arg1), arg2, arg3, arg4);
		}
		case LINUX_SYS_timerfd_settime: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4);
		}
		case LINUX_SYS_timerfd_gettime: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg2);
		}
#ifdef __NR_epoll_create
		case LINUX_SYS_epoll_create: {
			return install_local_fd(FS_SYSCALL(syscall, arg1), 0);
		}
#endif
		case LINUX_SYS_epoll_create1: {
			return install_local_fd(FS_SYSCALL(syscall, arg1), arg1);
		}
		case LINUX_SYS_readv:
		case LINUX_SYS_preadv:
		case LINUX_SYS_preadv2: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				const struct iovec *iov = (const struct iovec *)arg2;
				int iovcnt = arg3;
				// allocate buffer
				size_t total_bytes = 0;
				for (int i = 0; i < iovcnt; i++) {
					total_bytes += iov[i].iov_len;
				}
				size_t alloc_bytes = sizeof(*iov) * iovcnt + total_bytes;
				attempt_proxy_alloc_state remote_buf;
				attempt_proxy_alloc(alloc_bytes, thread, &remote_buf);
				// fill buffers
				intptr_t buf_cur = remote_buf.addr;
				struct iovec *iov_remote = malloc(sizeof(struct iovec) * iovcnt);
				struct attempt_cleanup_state state;
				attempt_push_free(thread, &state, iov_remote);
				for (int i = 0; i < iovcnt; i++) {
					iov_remote[i].iov_base = (void *)buf_cur;
					buf_cur += iov[i].iov_len;
					iov_remote[i].iov_len += iov[i].iov_len;
				}
				intptr_t result = proxy_poke(buf_cur, sizeof(*iov) * iovcnt, &iov_remote[0]);
				attempt_pop_free(&state);
				if (result >= 0) {
					// perform read remotely
					result = PROXY_LINUX_CALL(syscall, proxy_value(file.handle), proxy_value(remote_buf.addr), proxy_value(iovcnt), proxy_value(arg4), proxy_value(arg5), proxy_value(arg6));
					if (result >= 0) {
						// copy bytes into local buffers
						buf_cur = remote_buf.addr;
						for (int i = 0; i < iovcnt; i++) {
							if (result < (intptr_t)iov[i].iov_len) {
								intptr_t new_result = proxy_peek(buf_cur, iov[i].iov_len, iov[i].iov_base);
								if (new_result < 0) {
									result = new_result;
								}
								break;
							}
							intptr_t new_result = proxy_peek(buf_cur, result, iov[i].iov_base);
							if (new_result < 0) {
								result = new_result;
								break;
							}
							buf_cur += iov[i].iov_len;
						}
					}
				}
				// free buffers
				attempt_proxy_free(&remote_buf);
				return result;
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4, arg5, arg6);
		}
		case LINUX_SYS_writev:
		case LINUX_SYS_pwritev:
		case LINUX_SYS_pwritev2: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				const struct iovec *iov = (const struct iovec *)arg2;
				int iovcnt = arg3;
				// allocate buffer
				size_t total_bytes = 0;
				for (int i = 0; i < iovcnt; i++) {
					total_bytes += iov[i].iov_len;
				}
				size_t alloc_bytes = sizeof(*iov) * iovcnt + total_bytes;
				attempt_proxy_alloc_state remote_buf;
				attempt_proxy_alloc(alloc_bytes, thread, &remote_buf);
				// fill buffers
				intptr_t buf_cur = remote_buf.addr;
				struct iovec *iov_remote = malloc(sizeof(struct iovec) * iovcnt);
				struct attempt_cleanup_state state;
				attempt_push_free(thread, &state, iov_remote);
				intptr_t result = 0;
				for (int i = 0; i < iovcnt; i++) {
					iov_remote[i].iov_base = (void *)buf_cur;
					result = proxy_poke(buf_cur, iov[i].iov_len, iov[i].iov_base);
					if (result < 0) {
						attempt_pop_free(&state);
						goto pwrite_poke_failed;
					}
					buf_cur += iov[i].iov_len;
					iov_remote[i].iov_len += iov[i].iov_len;
				}
				result = proxy_poke(buf_cur, sizeof(*iov) * iovcnt, &iov_remote[0]);
				attempt_pop_free(&state);
				if (result >= 0) {
					// perform write remotely
					result = PROXY_LINUX_CALL(syscall, proxy_value(file.handle), proxy_value(remote_buf.addr), proxy_value(iovcnt), proxy_value(arg4), proxy_value(arg5), proxy_value(arg6));
				}
			pwrite_poke_failed:
				// free buffers
				attempt_proxy_free(&remote_buf);
				return result;
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4, arg5, arg6);
		}
		case LINUX_SYS_recvmmsg: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				struct mmsghdr *msgvec = (struct mmsghdr *)arg2;
				unsigned int vlen = arg3;
				int flags = arg4;
				// TODO: handle the timeout in arg5
				for (unsigned int i = 0; i < vlen; i++) {
					intptr_t result = vfs_call(recvmsg, file, &msgvec[i].msg_hdr, flags & ~MSG_WAITFORONE);
					if (result <= 0) {
						return i == 0 ? result : i;
					}
					msgvec[i].msg_len = (unsigned int)result;
					if (flags & MSG_WAITFORONE) {
						flags = (flags & ~MSG_WAITFORONE) | MSG_DONTWAIT;
					}
				}
				return vlen;
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4, arg5);
		}
		case LINUX_SYS_fanotify_init: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), arg1);
		}
		case LINUX_SYS_fanotify_mark: {
			int fanotify_fd = arg1;
			unsigned int flags = arg2;
			uint64_t mask = arg3;
			int dirfd = arg4;
			const char *pathname = (const char *)arg5;
			struct vfs_resolved_file file = vfs_resolve_file(fanotify_fd);
			struct vfs_resolved_path path = vfs_resolve_path(dirfd, pathname);
			if (vfs_is_remote_file(&file) != vfs_is_remote_path(&path)) {
				return invalid_local_remote_mixed_operation();
			}
			if (vfs_is_remote_file(&file)) {
				return PROXY_LINUX_CALL(LINUX_SYS_fanotify_mark, proxy_value(file.handle), proxy_value(flags), proxy_value(mask), proxy_value(path.info.handle), proxy_string(path.info.path));
			}
			return FS_SYSCALL(syscall, file.handle, flags, mask, path.info.handle, (intptr_t)path.info.path);
		}
		case LINUX_SYS_name_to_handle_at: {
			// TODO: handle name_to_handle_at
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4, arg5);
		}
		case LINUX_SYS_open_by_handle_at: {
			// TODO: handle open_by_handle_at
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return install_local_fd(FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4, arg5), arg5);
		}
		case LINUX_SYS_syncfs: {
			return vfs_call(syncfs, vfs_resolve_file(arg1));
		}
		case LINUX_SYS_sendmmsg: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				struct mmsghdr *msgvec = (struct mmsghdr *)arg2;
				unsigned int vlen = arg3;
				int flags = arg4;
				for (unsigned int i = 0; i < vlen; i++) {
					intptr_t result = vfs_call(sendmsg, file, &msgvec[i].msg_hdr, flags);
					if (result <= 0) {
						return i == 0 ? result : i;
					}
					msgvec[i].msg_len = (unsigned int)result;
				}
				return vlen;
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4, arg5);
		}
		case LINUX_SYS_setns: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg2);
		}
		case LINUX_SYS_finit_module: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3);
		}
		case LINUX_SYS_memfd_create: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), arg2);
		}
		case LINUX_SYS_copy_file_range: {
			return vfs_call(copy_file_range, vfs_resolve_file(arg1), (uint64_t *)arg2, vfs_resolve_file(arg2), (uint64_t *)arg3, arg4, arg5);
		}
#ifdef __NR_readlink
		case LINUX_SYS_readlink: {
			return vfs_call(readlinkat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), (char *)arg2, arg3);
		}
#endif
		case LINUX_SYS_readlinkat: {
			return vfs_call(readlinkat, vfs_resolve_path(arg1, (const char *)arg2), (char *)arg3, arg4);
		}
#ifdef __NR_mkdir
		case LINUX_SYS_mkdir: {
			return vfs_call(mkdirat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), arg2);
		}
#endif
		case LINUX_SYS_mkdirat: {
			return vfs_call(mkdirat, vfs_resolve_path(arg1, (const char *)arg2), arg3);
		}
#ifdef __NR_mknod
		case LINUX_SYS_mknod: {
			return vfs_call(mknodat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), arg2, arg3);
		}
#endif
		case LINUX_SYS_mknodat: {
			return vfs_call(mknodat, vfs_resolve_path(arg1, (const char *)arg2), arg3, arg4);
		}
#ifdef __NR_unlink
		case LINUX_SYS_unlink: {
			return vfs_call(unlinkat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), 0);
		}
		case LINUX_SYS_rmdir: {
			return vfs_call(unlinkat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), AT_REMOVEDIR);
		}
#endif
		case LINUX_SYS_unlinkat: {
			return vfs_call(unlinkat, vfs_resolve_path(arg1, (const char *)arg2), arg3);
		}
#ifdef __NR_rename
		case LINUX_SYS_rename: {
			return vfs_call(renameat2, vfs_resolve_path(AT_FDCWD, (const char *)arg1), vfs_resolve_path(AT_FDCWD, (const char *)arg2), 0);
		}
#endif
		case LINUX_SYS_renameat: {
			return vfs_call(renameat2, vfs_resolve_path(arg1, (const char *)arg2), vfs_resolve_path(arg3, (const char *)arg4), 0);
		}
		case LINUX_SYS_renameat2: {
			return vfs_call(renameat2, vfs_resolve_path(arg1, (const char *)arg2), vfs_resolve_path(arg3, (const char *)arg4), arg5);
		}
#ifdef __NR_link
		case LINUX_SYS_link: {
			return vfs_call(linkat, vfs_resolve_path(AT_FDCWD, (const char *)arg1), vfs_resolve_path(AT_FDCWD, (const char *)arg2), 0);
		}
#endif
		case LINUX_SYS_linkat: {
			return vfs_call(linkat, vfs_resolve_path(arg1, (const char *)arg2), vfs_resolve_path(arg3, (const char *)arg4), arg5);
		}
#ifdef __NR_symlink
		case LINUX_SYS_symlink: {
			return vfs_call(symlinkat, vfs_resolve_path(AT_FDCWD, (const char *)arg2), (const char *)arg1);
		}
#endif
		case LINUX_SYS_symlinkat: {
			return vfs_call(symlinkat, vfs_resolve_path(arg2, (const char *)arg3), (const char *)arg1);
		}
		case LINUX_SYS_fchmodat: {
			return vfs_call(fchmodat, vfs_resolve_path(arg1, (const char *)arg2), arg3, arg4);
		}
		case LINUX_SYS_rt_sigaction: {
			return handle_sigaction((int)arg1, (const struct fs_sigaction *)arg2, (struct fs_sigaction *)arg3, (size_t)arg4);
		}
		case LINUX_SYS_rt_sigprocmask: {
			int how = arg1;
			struct fs_sigset_t *nset = (struct fs_sigset_t *)arg2;
			struct fs_sigset_t *oset = (struct fs_sigset_t *)arg3;
			size_t sigsetsize = arg4;
			if (sigsetsize != sizeof(struct fs_sigset_t)) {
				return -EINVAL;
			}
			struct signal_state *signals = &thread->signals;
			if (context) {
				if (oset) {
					memcpy(oset, &signals->blocked_required, sizeof(struct fs_sigset_t));
				}
				if (nset) {
					switch (how) {
						case SIG_UNBLOCK: {
							signals->blocked_required.buf[0] &= ~nset->buf[0];
							struct fs_sigset_t *context_set = (struct fs_sigset_t *)&context->uc_sigmask;
							for (size_t i = 0; i < sigsetsize / sizeof(nset->buf[0]); i++) {
								context_set->buf[i] &= ~nset->buf[i];
							}
							// TODO: dispatch pending signals
							break;
						}
						case SIG_BLOCK: {
							signals->blocked_required.buf[0] |= nset->buf[0];
							struct fs_sigset_t *context_set = (struct fs_sigset_t *)&context->uc_sigmask;
							for (size_t i = 0; i < sigsetsize / sizeof(nset->buf[0]); i++) {
								context_set->buf[i] |= nset->buf[i];
							}
							context_set->buf[0] &= ~REQUIRED_SIGNALS;
							break;
						}
						case SIG_SETMASK: {
							signals->blocked_required.buf[0] = nset->buf[0];
							memcpy(&context->uc_sigmask, nset, sigsetsize);
							struct fs_sigset_t *context_set = (struct fs_sigset_t *)&context->uc_sigmask;
							context_set->buf[0] &= ~REQUIRED_SIGNALS;
							// TODO: dispatch pending signals
							break;
						}
					}
				}
				return 0;
			}
			struct fs_sigset_t copy;
			if (nset != NULL) {
				switch (how) {
					case SIG_UNBLOCK:
						signals->blocked_required.buf[0] &= ~nset->buf[0];
						// TODO: dispatch pending signals
						break;
					case SIG_BLOCK:
						signals->blocked_required.buf[0] |= nset->buf[0];
						if (nset->buf[0] & REQUIRED_SIGNALS) {
							// A required signal was blocked—copy to a local buffer and clear
							memcpy(&copy, nset, sigsetsize);
							copy.buf[0] &= ~REQUIRED_SIGNALS;
							nset = &copy;
						}
						break;
					case SIG_SETMASK:
						signals->blocked_required.buf[0] = nset->buf[0];
						if (nset->buf[0] & REQUIRED_SIGNALS) {
							// A required signal was blocked—copy to a local buffer and clear
							memcpy(&copy, nset, sigsetsize);
							copy.buf[0] &= ~REQUIRED_SIGNALS;
							nset = &copy;
							// TODO: dispatch pending signals
						}
						break;
				}
			}
			intptr_t result = fs_rt_sigprocmask(how, nset, oset, sigsetsize);
			if (result == 0 && oset) {
				oset->buf[0] = (oset->buf[0] & ~REQUIRED_SIGNALS) | (signals->blocked_required.buf[0] & REQUIRED_SIGNALS);
			}
			return result;
		}
#ifdef WATCH_ALTSTACKS
		case LINUX_SYS_sigaltstack: {
			const stack_t *ss = (const stack_t *)arg1;
			stack_t *old_ss = (stack_t *)arg2;
			if (ss != NULL) {
				struct stack_data *data = &thread->stack;
				data->altstack = *ss;
				return fs_sigaltstack(ss, old_ss);
			}
			int result = fs_sigaltstack(ss, old_ss);
			if (result == 0 && old_ss) {
				struct stack_data *data = &thread->stack;
				data->altstack = *old_ss;
			}
			return result;
		}
#endif
#ifdef __NR_fork
		case LINUX_SYS_fork: {
			return wrapped_fork(thread);
		}
#endif
#ifdef __NR_vfork
		case LINUX_SYS_vfork: {
			return wrapped_vfork(thread);
		}
#endif
		case LINUX_SYS_clone: {
			return wrapped_clone(thread, arg1, (void *)arg2, (int *)arg3, (int *)arg4, arg5);
		}
		case LINUX_SYS_clone3: {
			// for now, disable support for clone3
			return -ENOSYS;
		}
		case LINUX_SYS_munmap: {
			// workaround to handle case where a thread unmaps its stack and immediately exits
			// see musl's __pthread_exit function and the associated __unmapself helper
			intptr_t sp = context != NULL ? (intptr_t)context->uc_mcontext.REG_SP : (intptr_t)&sp;
			if (sp >= arg1 && sp <= arg1 + arg2) {
#ifdef ENABLE_TRACER
				if (enabled_traces & TRACE_TYPE_EXIT && fs_gettid() == get_self_pid()) {
					send_exit_event(thread, arg1);
				}
#endif
#ifdef COVERAGE
				if (fs_gettid() == get_self_pid()) {
					coverage_flush();
				}
#endif
				if (fs_gettid() == get_self_pid()) {
					clear_fd_table_for_exit(0);
				}
				attempt_exit(thread);
				call_on_alternate_stack(thread, unmap_and_exit_thread, (void *)arg1, (void *)arg2);
			}
			return FS_SYSCALL(LINUX_SYS_munmap, arg1, arg2);
		}
		case LINUX_SYS_exit:
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_EXIT && fs_gettid() == get_self_pid()) {
				send_exit_event(thread, arg1);
			}
#endif
#ifdef COVERAGE
			if (fs_gettid() == get_self_pid()) {
				coverage_flush();
			}
#endif
			if (fs_gettid() == get_self_pid()) {
				clear_fd_table_for_exit(arg1);
			}
			attempt_exit(thread);
			atomic_intptr_t *thread_id = clear_thread_storage();
			atomic_store_explicit(thread_id, 0, memory_order_release);
			fs_exitthread(arg1);
			__builtin_unreachable();
		case LINUX_SYS_exit_group:
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_EXIT) {
				send_exit_event(thread, arg1);
			}
#endif
#ifdef COVERAGE
			coverage_flush();
#endif
			clear_fd_table_for_exit(arg1);
			return FS_SYSCALL(LINUX_SYS_exit_group, arg1);
		case LINUX_SYS_chdir: {
			struct vfs_resolved_path resolved = vfs_resolve_path(AT_FDCWD, (const char *)arg1);
			if (vfs_is_remote_path(&resolved)) {
				struct vfs_resolved_file file;
				intptr_t result = vfs_install_file(vfs_call(openat, resolved, O_PATH | O_DIRECTORY, 0, &file), &file, 0);
				if (result < 0) {
					return result;
				}
				struct attempt_cleanup_state cleanup;
				vfs_attempt_push_close(thread, &cleanup, &file);
				result = perform_dup3(result, CWD_FD, 0);
				vfs_attempt_pop_close(&cleanup);
				return result;
			}
			if (resolved.info.handle != AT_FDCWD) {
				return invalid_local_operation();
			}
			int result = chdir_become_local_path(resolved.info.path);
#ifdef ENABLE_TRACER
			if (result == 0) {
				working_dir_changed(thread);
			}
#endif
			return result;
		}
		case LINUX_SYS_fchdir: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				struct fs_stat stat;
				intptr_t result = vfs_call(fstat, file, &stat);
				if (result < 0) {
					return result;
				}
				if (!S_ISDIR(stat.st_mode)) {
					return -ENOTDIR;
				}
				return perform_dup3(arg1, CWD_FD, 0);
			}
			int result = chdir_become_local_fd(file.handle);
#ifdef ENABLE_TRACER
			if (result == 0) {
				working_dir_changed(thread);
			}
#endif
			return result;
		}
		case LINUX_SYS_getcwd: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				char *buf = (char *)arg1;
				size_t size = (size_t)arg2;
				return vfs_call(readlink_fd, file, buf, size);
			}
			return FS_SYSCALL(syscall, arg1, arg2);
		}
		case LINUX_SYS_ptrace: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_PTRACE) {
				send_ptrace_attempt_event(thread, (int)arg1, (pid_t)arg2, (void *)arg3, (void *)arg4);
			}
#endif
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
		}
		case LINUX_SYS_process_vm_readv: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_PTRACE) {
				send_process_vm_readv_attempt_event(thread, (pid_t)arg1, (const struct iovec *)arg2, (unsigned long)arg3, (const struct iovec *)arg4, (unsigned long)arg5, (unsigned long)arg6);
			}
#endif
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
		}
		case LINUX_SYS_process_vm_writev: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_PTRACE) {
				send_process_vm_writev_attempt_event(thread, (pid_t)arg1, (const struct iovec *)arg2, (unsigned long)arg3, (const struct iovec *)arg4, (unsigned long)arg5, (unsigned long)arg6);
			}
#endif
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
		}
		case LINUX_SYS_socket: {
			return install_local_fd(FS_SYSCALL(LINUX_SYS_socket, arg1, arg2, arg3), (arg2 & SOCK_CLOEXEC) ? O_CLOEXEC : 0);
		}
		case LINUX_SYS_socketpair: {
			int domain = arg1;
			int type = arg2;
			int protocol = arg3;
			int *sv = (int *)arg4;
			if (sv == NULL) {
				return -EFAULT;
			}
			int local_sv[2];
			int result = FS_SYSCALL(LINUX_SYS_socketpair, domain, type, protocol, (intptr_t)&local_sv);
			if (result == 0) {
				int oflags = (type & SOCK_CLOEXEC) ? O_CLOEXEC : 0;
				int first = install_local_fd(local_sv[0], oflags);
				if (first < 0) {
					fs_close(local_sv[1]);
					return first;
				}
				int second = install_local_fd(local_sv[1], oflags);
				if (second < 0) {
					perform_close(first);
					return second;
				}
				// TODO: clean up first and second when writing to sv[0] or sv[1] faults
				sv[0] = first;
				sv[1] = second;
			}
			return result;
		}
		case LINUX_SYS_connect: {
			const struct sockaddr *addr = (const struct sockaddr *)arg2;
			union copied_sockaddr addr_buf;
			size_t size = (uintptr_t)arg3;
			struct vfs_resolved_file file;
			intptr_t result = vfs_resolve_socket_and_addr(thread, arg1, &addr, &size, &file, &addr_buf);
			if (result < 0) {
				return result;
			}
			return vfs_call(connect, file, addr, size);
		}
		case LINUX_SYS_bpf: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_BPF) {
				send_bpf_attempt_event(thread, arg1, (union bpf_attr *)arg2, (unsigned int)arg3);
			}
#endif
			switch (arg1) {
				case BPF_PROG_LOAD:
				case BPF_MAP_CREATE:
					return install_local_fd(FS_SYSCALL(syscall, arg1, arg2, arg3), O_CLOEXEC);
				case BPF_MAP_LOOKUP_ELEM:
				case BPF_MAP_UPDATE_ELEM:
				case BPF_MAP_DELETE_ELEM:
				case BPF_MAP_GET_NEXT_KEY: // TODO: handle client
					return FS_SYSCALL(syscall, arg1, arg2, arg3);
				default:
					return -EINVAL;
			}
		}
		case LINUX_SYS_brk: {
			intptr_t result = FS_SYSCALL(syscall, arg1);
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_BRK) {
				send_brk_result_event(thread, result);
			}
#endif
			return result;
		}
		case LINUX_SYS_ioctl: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_IOCTL) {
				send_ioctl_attempt_event(thread, (int)arg1, (unsigned long)arg2, arg3);
			}
#endif
			intptr_t result;
			switch (arg2) {
				case NS_GET_USERNS:
				case NS_GET_PARENT: {
					struct vfs_resolved_file file;
					result = vfs_install_file(vfs_call(ioctl_open_file, vfs_resolve_file(arg1), arg2, arg3, &file), &file, FD_CLOEXEC);
					break;
				}
				default:
					result = vfs_call(ioctl, vfs_resolve_file(arg1), arg2, arg3);
					break;
			}
			if (result == -ENOSYS && arg2 == TCGETS) {
				// TODO: Figure out why TCGETS returns -ENOSYS when called from
				// the trap, but not when called directly. This is only in test,
				// but something funky is going on.
				result = -ENOTTY;
			}
			return result;
		}
		case LINUX_SYS_listen: {
			return vfs_call(listen, vfs_resolve_file(arg1), arg2);
		}
		case LINUX_SYS_bind: {
			const struct sockaddr *addr = (struct sockaddr *)arg2;
			union copied_sockaddr addr_buf;
			size_t size = (uintptr_t)arg3;
			struct vfs_resolved_file file;
			intptr_t result = vfs_resolve_socket_and_addr(thread, arg1, &addr, &size, &file, &addr_buf);
			if (result < 0) {
				return result;
			}
			return vfs_call(bind, file, addr, size);
		}
		case LINUX_SYS_dup: {
			intptr_t result = perform_dup(arg1, 0);
#ifdef ENABLE_TRACER
			if (result >= 0) {
				if (enabled_traces & TRACE_TYPE_DUP) {
					// emulate a dup3
					send_dup3_attempt_event(thread, arg1, result, 0);
				}
			}
#endif
			return result;
		}
#ifdef __NR_dup2
		case LINUX_SYS_dup2: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_DUP) {
				send_dup3_attempt_event(thread, arg1, arg2, 0);
			}
#endif
			if (arg1 == arg2) {
				return arg1;
			}
			return perform_dup3(arg1, arg2, 0);
		}
#endif
		case LINUX_SYS_dup3: {
			if (arg1 == arg2) {
				return -EINVAL;
			}
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_DUP) {
				send_dup3_attempt_event(thread, arg1, arg2, arg3);
			}
#endif
			return perform_dup3(arg1, arg2, arg3);
		}
		case LINUX_SYS_fcntl: {
			switch (arg2) {
				case F_DUPFD: {
					intptr_t result = perform_dup(arg1, 0);
#ifdef ENABLE_TRACER
					if ((enabled_traces & TRACE_TYPE_DUP) && result >= 0) {
						// emulate a dup3
						send_dup3_attempt_event(thread, arg1, result, arg2 == F_DUPFD_CLOEXEC ? O_CLOEXEC : 0);
					}
#endif
					return result;
				}
				case F_DUPFD_CLOEXEC: {
					intptr_t result = perform_dup(arg1, O_CLOEXEC);
#ifdef ENABLE_TRACER
					if ((enabled_traces & TRACE_TYPE_DUP) && result >= 0) {
						// emulate a dup3
						send_dup3_attempt_event(thread, arg1, result, arg2 == F_DUPFD_CLOEXEC ? O_CLOEXEC : 0);
					}
#endif
					return result;
				}
				case F_SETFD:
					return perform_set_fd_flags(arg1, arg3);
				case F_GETFD:
					return perform_get_fd_flags(arg1);
				case F_SETFL:
				case F_GETFL:
				case F_SETLEASE:
				case F_GETLEASE:
				case F_SETPIPE_SZ:
				case F_GETPIPE_SZ:
				case F_ADD_SEALS:
				case F_GET_SEALS: {
					return vfs_call(fcntl_basic, vfs_resolve_file(arg1), arg2, arg3);
				}
				case F_GETLK:
				case F_SETLK:
				case F_SETLKW:
				case F_OFD_GETLK:
				case F_OFD_SETLK:
				case F_OFD_SETLKW: {
					return vfs_call(fcntl_lock, vfs_resolve_file(arg1), arg2, (struct flock *)arg3);
				}
				case FIONREAD:
				/*case TIOCINQ:*/
				case TIOCOUTQ: {
					return vfs_call(fcntl_int, vfs_resolve_file(arg1), arg2, (int *)arg3);
				}
				default: {
					return vfs_call(fcntl, vfs_resolve_file(arg1), arg2, arg3);
				}
			}
		}
		case LINUX_SYS_setrlimit: {
#ifdef ENABLE_TRACER
			if (arg1 == RLIMIT_STACK && (enabled_traces & TRACE_TYPE_RLIMIT) && arg2) {
				struct rlimit newlimit = *(const struct rlimit *)arg2;
				if (newlimit.rlim_cur == 18446744073709551615ull) {
					send_setrlimit_attempt_event(thread, 0, arg1, &newlimit);
				}
				return FS_SYSCALL(syscall, arg1, (intptr_t)&newlimit);
			}
#endif
			return FS_SYSCALL(syscall, arg1, arg2);
		}
		case LINUX_SYS_prlimit64: {
#ifdef ENABLE_TRACER
			if (arg2 == RLIMIT_STACK && (enabled_traces & TRACE_TYPE_RLIMIT) && arg3) {
				struct rlimit newlimit = *(const struct rlimit *)arg3;
				if (newlimit.rlim_cur == 18446744073709551615ull) {
					send_setrlimit_attempt_event(thread, arg1, arg2, &newlimit);
				}
				return FS_SYSCALL(syscall, arg1, arg2, (intptr_t)&newlimit, arg4);
			}
#endif
			return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4);
		}
		case LINUX_SYS_userfaultfd: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_USER_FAULT) {
				send_userfaultfd_attempt_event(thread, arg1);
			}
#endif
			return install_local_fd(FS_SYSCALL(syscall, arg1), arg1);
		}
		case LINUX_SYS_setuid: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_SETUID) {
				send_setuid_attempt_event(thread, arg1);
			}
#endif
			return FS_SYSCALL(syscall, arg1);
		}
		case LINUX_SYS_setreuid: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_SETUID) {
				send_setreuid_attempt_event(thread, arg1, arg2);
			}
#endif
			return FS_SYSCALL(syscall, arg1, arg2);
		}
		case LINUX_SYS_setresuid: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_SETUID) {
				uid_t *ruid = (uid_t *)arg1;
				uid_t *euid = (uid_t *)arg2;
				uid_t *suid = (uid_t *)arg3;
				send_setresuid_attempt_event(thread, ruid ? *ruid : (uid_t)-1, euid ? *euid : (uid_t)-1, suid ? *suid : (uid_t)-1);
			}
#endif
			return FS_SYSCALL(syscall, arg1, arg2, arg3);
		}
		case LINUX_SYS_setfsuid: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_SETUID) {
				send_setfsuid_attempt_event(thread, arg1);
			}
#endif
			return FS_SYSCALL(syscall, arg1);
		}
		case LINUX_SYS_setgid: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_SETGID) {
				send_setgid_attempt_event(thread, arg1);
			}
#endif
			return FS_SYSCALL(syscall, arg1);
		}
		case LINUX_SYS_setregid: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_SETGID) {
				send_setregid_attempt_event(thread, arg1, arg2);
			}
#endif
			return FS_SYSCALL(syscall, arg1, arg2);
		}
		case LINUX_SYS_setresgid: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_SETGID) {
				gid_t *rgid = (gid_t *)arg1;
				gid_t *egid = (gid_t *)arg2;
				gid_t *sgid = (gid_t *)arg3;
				send_setresgid_attempt_event(thread, rgid ? *rgid : (gid_t)-1, egid ? *egid : (gid_t)-1, sgid ? *sgid : (gid_t)-1);
			}
#endif
			return FS_SYSCALL(syscall, arg1, arg2, arg3);
		}
		case LINUX_SYS_setfsgid: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_SETGID) {
				send_setfsgid_attempt_event(thread, arg1);
			}
#endif
			return FS_SYSCALL(syscall, arg1);
		}
		case LINUX_SYS_getpid: {
			return get_self_pid();
		}
		case LINUX_SYS_gettid: {
			return fs_gettid();
		}
		case LINUX_SYS_sendto: {
			const struct sockaddr *addr = (struct sockaddr *)arg5;
			size_t size = (uintptr_t)arg6;
			union copied_sockaddr addr_buf;
			struct vfs_resolved_file file;
			intptr_t result = vfs_resolve_socket_and_addr(thread, arg1, &addr, &size, &file, &addr_buf);
			if (result < 0) {
				return result;
			}
			return vfs_call(sendto, file, (const void *)arg2, arg3, arg4, addr, size);
		}
		case LINUX_SYS_mprotect: {
#ifdef ENABLE_TRACER
			if (enabled_traces & TRACE_TYPE_MEMORY_PROTECTION && arg3 & PROT_EXEC) {
				send_mprotect_attempt_event(thread, (void *)arg1, arg2, arg3);
			}
#endif
			return FS_SYSCALL(syscall, arg1, arg2, arg3);
		}
#ifdef __NR_accept4
		case LINUX_SYS_accept4: {
			struct vfs_resolved_file file;
			return vfs_install_file(vfs_call(accept4, vfs_resolve_file(arg1), (struct sockaddr *)arg2, (socklen_t *)arg3, arg4, &file), &file, (arg4 & SOCK_CLOEXEC) ? FD_CLOEXEC : 0);
		}
#endif
		case LINUX_SYS_accept: {
			struct vfs_resolved_file file;
			return vfs_install_file(vfs_call(accept4, vfs_resolve_file(arg1), (struct sockaddr *)arg2, (socklen_t *)arg3, 0, &file), &file, 0);
		}
		case LINUX_SYS_read: {
			return vfs_call(read, vfs_resolve_file(arg1), (char *)arg2, arg3);
		}
		case LINUX_SYS_write: {
			return vfs_call(write, vfs_resolve_file(arg1), (const char *)arg2, arg3);
		}
		case LINUX_SYS_semget:
		case LINUX_SYS_shmget: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2, arg3), 0);
		}
		case LINUX_SYS_perf_event_open: {
			intptr_t arg2_fd;
			if (arg5 & PERF_FLAG_PID_CGROUP) {
				struct vfs_resolved_file file = vfs_resolve_file(arg1);
				if (vfs_is_remote_file(&file)) {
					invalid_remote_operation();
					return -EBADF;
				}
				arg2_fd = file.handle;
			} else {
				arg2_fd = arg2;
			}
			intptr_t arg4_fd;
			if (arg4 == -1) {
				arg4_fd = -1;
			} else {
				struct vfs_resolved_file file = vfs_resolve_file(arg4);
				if (vfs_is_remote_file(&file)) {
					invalid_remote_operation();
					return -EBADF;
				}
				arg4_fd = -1;
			}
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2_fd, arg3, arg4_fd, arg5), arg5 & PERF_FLAG_FD_CLOEXEC ? O_CLOEXEC : 0);
		}
		case LINUX_SYS_kexec_file_load: {
			struct vfs_resolved_file kernel_file = vfs_resolve_file(arg1);
			struct vfs_resolved_file initrd_file = vfs_resolve_file(arg2);
			if (vfs_is_remote_file(&kernel_file) || vfs_is_remote_file(&initrd_file)) {
				return -EINVAL;
			}
			return FS_SYSCALL(syscall, kernel_file.handle, initrd_file.handle, arg3, arg4, arg5);
		}
		case LINUX_SYS_tkill: {
			if (arg1 == fs_gettid()) {
				handle_raise(arg1, arg2);
			}
			break;
		}
		case LINUX_SYS_tgkill: {
			if (arg1 == get_self_pid() && arg2 == fs_gettid()) {
				handle_raise(arg2, arg3);
			}
			break;
		}
		case LINUX_SYS_pidfd_open: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), O_CLOEXEC);
		}
		case LINUX_SYS_pidfd_send_signal: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4);
		}
#ifdef __NR_pidfd_getfd
		case LINUX_SYS_pidfd_getfd: {
			// disable pidfd_getfd because it's impossible
			return -ENOSYS;
		}
#endif
		case LINUX_SYS_io_uring_setup:
		case LINUX_SYS_io_uring_enter:
		case LINUX_SYS_io_uring_register: {
			// disable io_uring because it's not possible to proxy it
			return -ENOSYS;
		}
		case LINUX_SYS_open_tree: {
			struct vfs_resolved_path path = vfs_resolve_path(arg1, (const char *)arg2);
			if (vfs_is_remote_path(&path)) {
				return invalid_remote_operation();
			}
			return FS_SYSCALL(syscall, path.info.handle, (intptr_t)path.info.path, arg3);
		}
		case LINUX_SYS_move_mount: {
			struct vfs_resolved_path from = vfs_resolve_path(arg1, (const char *)arg2);
			struct vfs_resolved_path to = vfs_resolve_path(arg3, (const char *)arg4);
			if (vfs_is_remote_path(&from) || vfs_is_remote_path(&to)) {
				if (vfs_is_remote_path(&from) != vfs_is_remote_path(&to)) {
					return invalid_local_remote_mixed_operation();
				}
				return PROXY_LINUX_CALL(LINUX_SYS_move_mount, proxy_value(from.info.handle), proxy_string(from.info.path), proxy_value(to.info.handle), proxy_string(to.info.path), proxy_value(arg5));
			}
			return FS_SYSCALL(syscall, from.info.handle, (intptr_t)from.info.path, to.info.handle, (intptr_t)to.info.path, arg5);
		}
		case LINUX_SYS_fsopen: {
			return install_local_fd(FS_SYSCALL(syscall, arg1, arg2), (arg2 & FSOPEN_CLOEXEC) ? O_CLOEXEC : 0);
		}
		case LINUX_SYS_fsconfig: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return PROXY_LINUX_CALL(LINUX_SYS_fsconfig, proxy_value(file.handle), proxy_value(arg2), proxy_string((const char *)arg3), proxy_string((const char *)arg4), proxy_value(arg5));
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3, arg4, arg5);
		}
		case LINUX_SYS_fsmount: {
			struct vfs_resolved_file file = vfs_resolve_file(arg1);
			if (vfs_is_remote_file(&file)) {
				return PROXY_LINUX_CALL(LINUX_SYS_fsmount, proxy_value(file.handle), proxy_value(arg2), proxy_value(arg3));
			}
			return FS_SYSCALL(syscall, file.handle, arg2, arg3);
		}
		case LINUX_SYS_fspick: {
			struct vfs_resolved_path path = vfs_resolve_path(arg1, (const char *)arg2);
			if (vfs_is_remote_path(&path)) {
				return PROXY_LINUX_CALL(LINUX_SYS_fspick, proxy_value(path.info.handle), proxy_string(path.info.path), proxy_value(arg3));
			}
			return FS_SYSCALL(syscall, path.info.handle, (intptr_t)path.info.path, arg3);
		}
		case 0x666: {
			return (intptr_t)&fd_table;
		}
	}
	return FS_SYSCALL(syscall, arg1, arg2, arg3, arg4, arg5, arg6);
}
