#define _GNU_SOURCE

#include "intercept.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>

#include "attempt.h"
#include "exec.h"
#include "axon.h"
#include "handler.h"
#include "tls.h"
#include "patch.h"
#include "stack.h"

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif

void __restore();

struct intercept_action {
	struct fs_sigaction *inferior;
	void (*handler)(int);
};

typedef void (*signal_handler)(int, siginfo_t *, void *);

static struct fs_mutex signal_lock;

static struct fs_sigaction sigsys;
static void sigsys_handler(int nr, siginfo_t *info, void *void_context);

static struct fs_sigaction sigsegv;
static struct fs_sigaction sigtrap;
static void crash_handler(int nr, siginfo_t *info, void *void_context);

#ifdef PATCH_HANDLES_SIGILL
static struct fs_sigaction sigill;
static void sigill_handler(int nr, siginfo_t *info, void *void_context);
#endif

static struct intercept_action action_for_signal(int nr)
{
	switch (nr) {
		case SIGSYS:
			return (struct intercept_action){
				.inferior = &sigsys,
				.handler = (void *)&sigsys_handler,
			};
		case SIGSEGV:
			return (struct intercept_action){
				.inferior = &sigsegv,
				.handler = (void *)&crash_handler,
			};
		case SIGTRAP:
			return (struct intercept_action){
				.inferior = &sigtrap,
				.handler = (void *)&crash_handler,
			};
#ifdef PATCH_HANDLES_SIGILL
		case SIGILL:
			return (struct intercept_action){
				.inferior = &sigill,
				.handler = (void *)&sigill_handler,
			};
#endif
		default:
			return (struct intercept_action){ 0 };
	}
}

static void empty_handler(__attribute__((unused)) int nr, __attribute__((unused)) siginfo_t *info, __attribute__((unused)) void *void_context)
{
}

static void default_handler(__attribute__((unused)) int nr, __attribute__((unused)) siginfo_t *info, __attribute__((unused)) void *void_context)
{
	// Reset handler to apply the default action
	struct fs_sigaction sa = {
		.handler = SIG_DFL,
		.flags = SA_RESTORER,
		.restorer = (void *)&__restore,
		.mask = { 0 },
	};
	int sa_result = fs_rt_sigaction(nr, &sa, NULL, sizeof(struct fs_sigset_t));
	if (sa_result < 0) {
		DIE("failed to reset sigaction", fs_strerror(sa_result));
	}
	// And resend the signal now that the handler has been unset
	if (nr == SIGSYS) {
		int kill_result = fs_tkill(fs_gettid(), nr);
		if (kill_result < 0) {
			DIE("failed to resend signal", fs_strerror(sa_result));
		}
	}
}

static signal_handler get_next_handler(struct thread_storage *tls, int nr)
{
	// Check if signal is blocked and make pending if so
	if (fs_sigismember(&tls->signals.blocked_required, nr)) {
		switch (nr) {
			case SIGBUS:
			case SIGFPE:
			case SIGILL:
			case SIGSEGV:
				// These signals cannot be pending, apply the default action
				return default_handler;
		}
		fs_sigaddset(&tls->signals.pending_required, nr);
		return empty_handler;
	}
	// Read the sigaction state
	struct intercept_action action = action_for_signal(nr);
	if (!action.inferior) {
		return empty_handler;
	}
	fs_mutex_lock(&signal_lock);
	struct fs_sigaction copy = *action.inferior;
	if (copy.flags & SA_RESETHAND) {
		action.inferior->handler = SIG_DFL;
	}
	fs_mutex_unlock(&signal_lock);
	// Dispatch the signal handler
	if (copy.handler == SIG_DFL) {
		return default_handler;
	}
	if (copy.handler != SIG_IGN) {
		// Send to the program's signal handler
		return (signal_handler)(void *)copy.handler;
	}
	return empty_handler;
}

struct syscall_main_data {
	intptr_t syscall;
	ucontext_t *ctx;
	intptr_t result;
};

static void syscall_body(struct thread_storage *thread, void *d)
{
	struct syscall_main_data *data = d;
	mcontext_t *ctx = &data->ctx->uc_mcontext;
	switch (data->syscall) {
		case __NR_execve:
		case __NR_execveat:
		case __NR_exit_group:
		case __NR_exit:
#ifdef __NR_vfork
		case __NR_vfork:
#endif
#ifdef __NR_fork
		case __NR_fork:
#endif
		case __NR_clone:
			// Don't bother to patch certain syscalls
			break;
		default:
			patch_syscall(thread, (ins_ptr)ctx->REG_PC, ctx->REG_SP, ctx->REG_BP, SELF_FD);
			break;
	}
#ifdef REG_ARG6
	data->result = handle_syscall(thread, data->syscall, ctx->REG_ARG1, ctx->REG_ARG2, ctx->REG_ARG3, ctx->REG_ARG4, ctx->REG_ARG5, ctx->REG_ARG6, data->ctx);
#else
	data->result = handle_syscall(thread, data->syscall, ctx->REG_ARG1, ctx->REG_ARG2, ctx->REG_ARG3, ctx->REG_ARG4, ctx->REG_ARG5, 0, data->ctx);
#endif
}

// sigsys_handler receives intercepted syscalls, patches the syscall instruction if possible,
// and forwards to the syscall handler
static void sigsys_handler(int nr, siginfo_t *info, void *void_context)
{
	struct thread_storage *thread = get_thread_storage();
	if (nr == SIGSYS && info->si_code == SYS_SECCOMP && void_context) {
		intptr_t syscall = info->si_syscall;
		struct syscall_main_data data = {
			.syscall = syscall,
			.ctx = void_context,
			.result = -EFAULT,
		};
		attempt_with_sufficient_stack(thread, syscall_body, &data);
		mcontext_t *ctx = &((ucontext_t *)void_context)->uc_mcontext;
		intptr_t result = data.result;
		if (result == -ENOSYS) {
#ifdef REG_ARG6
			result = FS_SYSCALL(syscall, ctx->REG_ARG1, ctx->REG_ARG2, ctx->REG_ARG3, ctx->REG_ARG4, ctx->REG_ARG5, ctx->REG_ARG6);
#else
			result = FS_SYSCALL(syscall, ctx->REG_ARG1, ctx->REG_ARG2, ctx->REG_ARG3, ctx->REG_ARG4, ctx->REG_ARG5);
#endif
		}
		ctx->REG_RESULT = result;
		return;
	}
	signal_handler handler = get_next_handler(thread, nr);
	return handler(nr, info, void_context);
}

static void crash_handler(int nr, siginfo_t *info, void *void_context)
{
	struct thread_storage *thread = get_thread_storage();
	if (info != NULL && void_context) {
		if (attempt_handle_fault(thread, void_context)) {
			return;
		}
	}
	signal_handler handler = get_next_handler(thread, nr);
	return handler(nr, info, void_context);
}

#ifdef PATCH_HANDLES_SIGILL

static void sigill_handler(int nr, siginfo_t *info, void *void_context)
{
	struct thread_storage *thread = get_thread_storage();
	if (patch_handle_illegal_instruction(thread, void_context)) {
		return;
	}
	signal_handler handler = get_next_handler(thread, nr);
	return handler(nr, info, void_context);
}

#endif

// intercept_sigsys will interrupt the SIGSYS system call and call the appropriate handler
int intercept_signals(void) {
	// Set a handler to handle SIGSYS signals
	struct fs_sigaction sa = {
		.handler = (void *)&sigsys_handler,
		.flags = SA_RESTORER|SA_SIGINFO|SA_NODEFER,
		.restorer = (void *)&__restore,
		.mask = { ~0l },
	};
	// Block all signals except for signals used internally
	fs_sigdelset(&sa.mask, SIGSEGV);
	fs_sigdelset(&sa.mask, SIGTRAP);
	fs_sigdelset(&sa.mask, SIGILL);
	fs_sigdelset(&sa.mask, SIGSYS);

	int result = fs_rt_sigaction(SIGSYS, &sa, NULL, sizeof(struct fs_sigset_t));
	if (result) {
		return result;
	}

	// Set a handler to handle SIGSEGV and SIGTRAP signals
	sa.handler = (void *)&crash_handler;
	result = fs_rt_sigaction(SIGSEGV, &sa, NULL, sizeof(struct fs_sigset_t));
	if (result) {
		return result;
	}
	result = fs_rt_sigaction(SIGTRAP, &sa, NULL, sizeof(struct fs_sigset_t));
	if (result) {
		return result;
	}

#ifdef PATCH_HANDLES_SIGILL
	// Set a handler to handle SIGILL signals
	sa.handler = (void *)&sigill_handler;
	result = fs_rt_sigaction(SIGILL, &sa, NULL, sizeof(struct fs_sigset_t));
	if (result) {
		return result;
	}
#endif

	// Unblock SIGSYS, SIGSEGV and SIGILL
	struct fs_sigset_t set = { 0 };
	fs_sigaddset(&set, SIGSYS);
	fs_sigaddset(&set, SIGSEGV);
	fs_sigaddset(&set, SIGTRAP);
#ifdef PATCH_HANDLES_SIGILL
	fs_sigaddset(&set, SIGILL);
#endif
	return fs_rt_sigprocmask(SIG_UNBLOCK, &set, NULL, sizeof(struct fs_sigset_t));
}

int handle_sigaction(int signal, const struct fs_sigaction *act, struct fs_sigaction *oldact, size_t size)
{
	struct intercept_action signal_block = action_for_signal(signal);
	if (!signal_block.handler) {
		struct fs_sigaction actcopy;
		if (act) {
			fs_memcpy(&actcopy, act, sizeof(actcopy));
			actcopy.mask.buf[0] &= REQUIRED_SIGNALS;
			act = &actcopy;
		}
		return fs_rt_sigaction(signal, act, oldact, size);
	}
	struct attempt_cleanup_state lock_cleanup;
	attempt_lock_and_push_mutex(get_thread_storage(), &lock_cleanup, &signal_lock);
	if (act) {
		unsigned long new_onstack = act->flags & SA_ONSTACK;
		if ((signal_block.inferior->flags & SA_ONSTACK) != new_onstack) {
			struct fs_sigaction sa = {
				.handler = signal_block.handler,
				.flags = SA_RESTORER|SA_SIGINFO|new_onstack,
				.restorer = (void *)&__restore,
				.mask = { 0 },
			};
			int result = fs_rt_sigaction(signal, &sa, NULL, sizeof(struct fs_sigset_t));
			if (result != 0) {
				attempt_unlock_and_pop_mutex(&lock_cleanup, &signal_lock);
				return result;
			}
		}
	}
	if (oldact) {
		*oldact = *signal_block.inferior;
	}
	if (act) {
		*signal_block.inferior = *act;
	}
	attempt_unlock_and_pop_mutex(&lock_cleanup, &signal_lock);
	return 0;
}

void handle_raise(int tid, int sig)
{
	(void)tid;
	(void)sig;
}
