#define _GNU_SOURCE
#include "callander_print.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/user.h>
#include <termios.h>

__attribute__((nonnull(1)))
char *copy_register_state_description(const struct loader_context *context, struct register_state reg)
{
	if (register_is_exactly_known(&reg)) {
		if (reg.value == 0xffffff9c) {
			char *buf = malloc(sizeof("AT_FDCWD"));
			fs_memcpy(buf, "AT_FDCWD", sizeof("AT_FDCWD"));
			return buf;
		}
		if (reg.value == 0xffffffff) {
			char *buf = malloc(sizeof("-1 as u32"));
			fs_memcpy(buf, "-1 as u32", sizeof("-1 as u32"));
			return buf;
		}
		if ((uintptr_t)reg.value < PAGE_SIZE) {
			char *buf = malloc(5);
			fs_utoa(reg.value, buf);
			return buf;
		}
		return copy_address_description(context, (const void *)reg.value);
	}
	if (register_is_partially_known(&reg)) {
		if (reg.value == 1 && reg.max == ~(uintptr_t)0) {
			char *result = malloc(sizeof("non-NULL"));
			memcpy(result, "non-NULL", sizeof("non-NULL"));
			return result;
		}
		if (reg.value == 0) {
			if (reg.max == 0xffffffff) {
				char *result = malloc(sizeof("any u32"));
				memcpy(result, "any u32", sizeof("any u32"));
				return result;
			}
			if (reg.max == 0xffff) {
				char *result = malloc(sizeof("any u16"));
				memcpy(result, "any u16", sizeof("any u16"));
				return result;
			}
			if (reg.max == 0xff) {
				char *result = malloc(sizeof("any u8"));
				memcpy(result, "any u8", sizeof("any u8"));
				return result;
			}
		}
		char *min = copy_address_description(context, (const void *)reg.value);
		size_t min_size = fs_strlen(min);
		char *max = copy_address_description(context, (const void *)reg.max);
		size_t max_size = fs_strlen(max);
		char *result = malloc(min_size + max_size + 2);
		fs_memcpy(result, min, min_size);
		result[min_size] = '-';
		fs_memcpy(&result[min_size+1], max, max_size + 1);
		free(min);
		free(max);
		return result;
	}
	char *result = malloc(sizeof("any"));
	memcpy(result, "any", sizeof("any"));
	return result;
}

struct enum_option {
	uintptr_t value;
	const char *description;
};

#define DESCRIBE_ENUM(x) { .value = x, .description = #x }

#define DESCRIBE_FLAG(X) [(__builtin_popcount(X) == 1 ? (unsigned) (8*sizeof (unsigned long long) - __builtin_clzll((X)) - 1) : (unsigned)-1)] = #X

struct enum_option prots[] = {
	DESCRIBE_ENUM(PROT_NONE),
};

static const char *prot_flags[64] = {
	DESCRIBE_FLAG(PROT_READ),
	DESCRIBE_FLAG(PROT_WRITE),
	DESCRIBE_FLAG(PROT_EXEC),
};

static struct enum_option maps[] = {
	// DESCRIBE_ENUM(MAP_FILE),
	DESCRIBE_ENUM(MAP_SHARED),
	DESCRIBE_ENUM(MAP_PRIVATE),
	DESCRIBE_ENUM(MAP_SHARED_VALIDATE),
};

static const char *map_flags[64] = {
	DESCRIBE_FLAG(MAP_32BIT),
	DESCRIBE_FLAG(MAP_ANONYMOUS),
	DESCRIBE_FLAG(MAP_DENYWRITE),
	DESCRIBE_FLAG(MAP_EXECUTABLE),
	DESCRIBE_FLAG(MAP_FIXED),
	DESCRIBE_FLAG(MAP_FIXED_NOREPLACE),
	DESCRIBE_FLAG(MAP_GROWSDOWN),
	DESCRIBE_FLAG(MAP_HUGETLB),
	// DESCRIBE_FLAG(MAP_HUGE_2MB),
	// DESCRIBE_FLAG(MAP_HUGE_1GB),
	DESCRIBE_FLAG(MAP_LOCKED),
	DESCRIBE_FLAG(MAP_NORESERVE),
	DESCRIBE_FLAG(MAP_POPULATE),
	DESCRIBE_FLAG(MAP_STACK),
	DESCRIBE_FLAG(MAP_SYNC),
	// DESCRIBE_FLAG(MAP_UNINITIALIZED),
};

static const char *remap_flags[64] = {
	DESCRIBE_FLAG(MREMAP_MAYMOVE),
	DESCRIBE_FLAG(MREMAP_FIXED),
};

#ifdef O_LARGEFILE
#undef O_LARGEFILE
#endif
#define O_LARGEFILE	00100000

static struct enum_option opens[] = {
	DESCRIBE_ENUM(O_RDONLY),
	DESCRIBE_ENUM(O_WRONLY),
	DESCRIBE_ENUM(O_RDWR),
};

static const char *open_flags[64] = {
	DESCRIBE_FLAG(O_APPEND),
	DESCRIBE_FLAG(O_ASYNC),
	DESCRIBE_FLAG(O_CLOEXEC),
	DESCRIBE_FLAG(O_CREAT),
	DESCRIBE_FLAG(O_DIRECT),
	DESCRIBE_FLAG(O_DIRECTORY),
	DESCRIBE_FLAG(O_DSYNC),
	DESCRIBE_FLAG(O_EXCL),
	DESCRIBE_FLAG(O_LARGEFILE),
	DESCRIBE_FLAG(O_NOATIME),
	// DESCRIBE_FLAG(O_NOCTTY),
	DESCRIBE_FLAG(O_NOFOLLOW),
	DESCRIBE_FLAG(O_NONBLOCK),
	DESCRIBE_FLAG(O_PATH),
	// DESCRIBE_FLAG(O_SYNC),
	// DESCRIBE_FLAG(O_TMPFILE),
	DESCRIBE_FLAG(O_TRUNC),
};

static struct enum_option access_modes[] = {
	DESCRIBE_ENUM(F_OK),
};

static const char *access_mode_flags[64] = {
	DESCRIBE_FLAG(R_OK),
	DESCRIBE_FLAG(W_OK),
	DESCRIBE_FLAG(X_OK),
};

static struct enum_option shutdown_hows[] = {
	DESCRIBE_ENUM(SHUT_RD),
	DESCRIBE_ENUM(SHUT_WR),
	DESCRIBE_ENUM(SHUT_RDWR),
};

static const char *accessat_flags[64] = {
	DESCRIBE_FLAG(AT_EACCESS),
	DESCRIBE_FLAG(AT_SYMLINK_NOFOLLOW),
	DESCRIBE_FLAG(AT_SYMLINK_FOLLOW),
	DESCRIBE_FLAG(AT_NO_AUTOMOUNT),
	DESCRIBE_FLAG(AT_EMPTY_PATH),
	DESCRIBE_FLAG(AT_STATX_FORCE_SYNC),
	DESCRIBE_FLAG(AT_STATX_DONT_SYNC),
	DESCRIBE_FLAG(AT_RECURSIVE),
	// DESCRIBE_FLAG(AT_HANDLE_FID), // conflicts with AT_EACCESS
};

static const char *removeat_flags[64] = {
	DESCRIBE_FLAG(AT_SYMLINK_NOFOLLOW),
	DESCRIBE_FLAG(AT_REMOVEDIR),
	DESCRIBE_FLAG(AT_SYMLINK_FOLLOW),
	DESCRIBE_FLAG(AT_NO_AUTOMOUNT),
	DESCRIBE_FLAG(AT_EMPTY_PATH),
	DESCRIBE_FLAG(AT_STATX_FORCE_SYNC),
	DESCRIBE_FLAG(AT_STATX_DONT_SYNC),
	DESCRIBE_FLAG(AT_RECURSIVE),
	// DESCRIBE_FLAG(AT_HANDLE_FID), // conflicts with AT_REMOVEDIR
};

static const char *msync_flags[64] = {
	DESCRIBE_FLAG(MS_ASYNC),
	DESCRIBE_FLAG(MS_SYNC),
	DESCRIBE_FLAG(MS_INVALIDATE),
};

// glibc defines these
#define SIGCANCEL       __SIGRTMIN
#define SIGSETXID       (__SIGRTMIN + 1)

static struct enum_option signums[] = {
	DESCRIBE_ENUM(SIGHUP),
	DESCRIBE_ENUM(SIGINT),
	DESCRIBE_ENUM(SIGQUIT),
	DESCRIBE_ENUM(SIGILL),
	DESCRIBE_ENUM(SIGTRAP),
	DESCRIBE_ENUM(SIGABRT),
	DESCRIBE_ENUM(SIGBUS),
	DESCRIBE_ENUM(SIGFPE),
	DESCRIBE_ENUM(SIGKILL),
	DESCRIBE_ENUM(SIGUSR1),
	DESCRIBE_ENUM(SIGSEGV),
	DESCRIBE_ENUM(SIGUSR2),
	DESCRIBE_ENUM(SIGPIPE),
	DESCRIBE_ENUM(SIGALRM),
	DESCRIBE_ENUM(SIGTERM),
	DESCRIBE_ENUM(SIGSTKFLT),
	DESCRIBE_ENUM(SIGCHLD),
	DESCRIBE_ENUM(SIGCONT),
	DESCRIBE_ENUM(SIGSTOP),
	DESCRIBE_ENUM(SIGTSTP),
	DESCRIBE_ENUM(SIGTTIN),
	DESCRIBE_ENUM(SIGTTOU),
	DESCRIBE_ENUM(SIGURG),
	DESCRIBE_ENUM(SIGXCPU),
	DESCRIBE_ENUM(SIGXFSZ),
	DESCRIBE_ENUM(SIGVTALRM),
	DESCRIBE_ENUM(SIGPROF),
	DESCRIBE_ENUM(SIGWINCH),
	DESCRIBE_ENUM(SIGIO),
	DESCRIBE_ENUM(SIGPWR),
	DESCRIBE_ENUM(SIGSYS),
	DESCRIBE_ENUM(SIGCANCEL),
	DESCRIBE_ENUM(SIGSETXID),
};

static struct enum_option ioctls[] = {
    DESCRIBE_ENUM(TCGETS),
    DESCRIBE_ENUM(TCSETS),
    DESCRIBE_ENUM(TCSETSW),
    DESCRIBE_ENUM(TCSETSF),
    DESCRIBE_ENUM(TCGETA),
    DESCRIBE_ENUM(TCSETA),
    DESCRIBE_ENUM(TCSETAW),
    DESCRIBE_ENUM(TCSETAF),
    DESCRIBE_ENUM(TCSBRK),
    DESCRIBE_ENUM(TCXONC),
    DESCRIBE_ENUM(TCFLSH),
    DESCRIBE_ENUM(TIOCEXCL),
    DESCRIBE_ENUM(TIOCNXCL),
    DESCRIBE_ENUM(TIOCSCTTY),
    DESCRIBE_ENUM(TIOCGPGRP),
    DESCRIBE_ENUM(TIOCSPGRP),
    DESCRIBE_ENUM(TIOCOUTQ),
    DESCRIBE_ENUM(TIOCSTI),
    DESCRIBE_ENUM(TIOCGWINSZ),
    DESCRIBE_ENUM(TIOCSWINSZ),
    DESCRIBE_ENUM(TIOCMGET),
    DESCRIBE_ENUM(TIOCMBIS),
    DESCRIBE_ENUM(TIOCMBIC),
    DESCRIBE_ENUM(TIOCMSET),
    DESCRIBE_ENUM(TIOCGSOFTCAR),
    DESCRIBE_ENUM(TIOCSSOFTCAR),
    DESCRIBE_ENUM(FIONREAD),
    DESCRIBE_ENUM(TIOCLINUX),
    DESCRIBE_ENUM(TIOCCONS),
    DESCRIBE_ENUM(TIOCGSERIAL),
    DESCRIBE_ENUM(TIOCSSERIAL),
    DESCRIBE_ENUM(TIOCPKT),
    DESCRIBE_ENUM(FIONBIO),
    DESCRIBE_ENUM(TIOCNOTTY),
    DESCRIBE_ENUM(TIOCSETD),
    DESCRIBE_ENUM(TIOCGETD),
    DESCRIBE_ENUM(TCSBRKP),
    DESCRIBE_ENUM(TIOCSBRK),
    DESCRIBE_ENUM(TIOCCBRK),
    DESCRIBE_ENUM(TIOCGSID),
    // DESCRIBE_ENUM(TCGETS2),
    // DESCRIBE_ENUM(TCSETS2),
    // DESCRIBE_ENUM(TCSETSW2),
    // DESCRIBE_ENUM(TCSETSF2),
    DESCRIBE_ENUM(TIOCGRS485),
    DESCRIBE_ENUM(TIOCSRS485),
    DESCRIBE_ENUM(TIOCGPTN),
    DESCRIBE_ENUM(TIOCSPTLCK),
    DESCRIBE_ENUM(TCGETX),
    DESCRIBE_ENUM(TCSETX),
    DESCRIBE_ENUM(TCSETXF),
    DESCRIBE_ENUM(TCSETXW),
    DESCRIBE_ENUM(FIONCLEX),
    DESCRIBE_ENUM(FIOCLEX),
    DESCRIBE_ENUM(FIOASYNC),
    DESCRIBE_ENUM(TIOCSERCONFIG),
    DESCRIBE_ENUM(TIOCSERGWILD),
    DESCRIBE_ENUM(TIOCSERSWILD),
    DESCRIBE_ENUM(TIOCGLCKTRMIOS),
    DESCRIBE_ENUM(TIOCSLCKTRMIOS),
    DESCRIBE_ENUM(TIOCSERGSTRUCT),
    DESCRIBE_ENUM(TIOCSERGETLSR),
    DESCRIBE_ENUM(TIOCSERGETMULTI),
    DESCRIBE_ENUM(TIOCSERSETMULTI),
    DESCRIBE_ENUM(TIOCMIWAIT),
    DESCRIBE_ENUM(TIOCGICOUNT),
    // DESCRIBE_ENUM(TIOCGHAYESESP),
    // DESCRIBE_ENUM(TIOCSHAYESESP),
    DESCRIBE_ENUM(FIOQSIZE),
    DESCRIBE_ENUM(SIOCADDRT),
    DESCRIBE_ENUM(SIOCDELRT),
    DESCRIBE_ENUM(SIOCRTMSG),
    DESCRIBE_ENUM(SIOCGIFNAME),
    DESCRIBE_ENUM(SIOCSIFLINK),
    DESCRIBE_ENUM(SIOCGIFCONF),
    DESCRIBE_ENUM(SIOCGIFFLAGS),
    DESCRIBE_ENUM(SIOCSIFFLAGS),
    DESCRIBE_ENUM(SIOCGIFADDR),
    DESCRIBE_ENUM(SIOCSIFADDR),
    DESCRIBE_ENUM(SIOCGIFDSTADDR),
    DESCRIBE_ENUM(SIOCSIFDSTADDR),
    DESCRIBE_ENUM(SIOCGIFBRDADDR),
    DESCRIBE_ENUM(SIOCSIFBRDADDR),
    DESCRIBE_ENUM(SIOCGIFNETMASK),
    DESCRIBE_ENUM(SIOCSIFNETMASK),
    DESCRIBE_ENUM(SIOCGIFMETRIC),
    DESCRIBE_ENUM(SIOCSIFMETRIC),
    DESCRIBE_ENUM(SIOCGIFMEM),
    DESCRIBE_ENUM(SIOCSIFMEM),
    DESCRIBE_ENUM(SIOCGIFMTU),
    DESCRIBE_ENUM(SIOCSIFMTU),
    DESCRIBE_ENUM(SIOCSIFNAME),
    DESCRIBE_ENUM(SIOCSIFHWADDR),
    DESCRIBE_ENUM(SIOCGIFENCAP),
    DESCRIBE_ENUM(SIOCSIFENCAP),
    DESCRIBE_ENUM(SIOCGIFHWADDR),
    DESCRIBE_ENUM(SIOCGIFSLAVE),
    DESCRIBE_ENUM(SIOCSIFSLAVE),
    DESCRIBE_ENUM(SIOCADDMULTI),
    DESCRIBE_ENUM(SIOCDELMULTI),
    DESCRIBE_ENUM(SIOCGIFINDEX),
    DESCRIBE_ENUM(SIOCSIFPFLAGS),
    DESCRIBE_ENUM(SIOCGIFPFLAGS),
    DESCRIBE_ENUM(SIOCDIFADDR),
    DESCRIBE_ENUM(SIOCSIFHWBROADCAST),
    DESCRIBE_ENUM(SIOCGIFCOUNT),
    DESCRIBE_ENUM(SIOCGIFBR),
    DESCRIBE_ENUM(SIOCSIFBR),
    DESCRIBE_ENUM(SIOCGIFTXQLEN),
    DESCRIBE_ENUM(SIOCSIFTXQLEN),
    DESCRIBE_ENUM(SIOCDARP),
    DESCRIBE_ENUM(SIOCGARP),
    DESCRIBE_ENUM(SIOCSARP),
    DESCRIBE_ENUM(SIOCDRARP),
    DESCRIBE_ENUM(SIOCGRARP),
    DESCRIBE_ENUM(SIOCSRARP),
    DESCRIBE_ENUM(SIOCGIFMAP),
    DESCRIBE_ENUM(SIOCSIFMAP),
    DESCRIBE_ENUM(SIOCADDDLCI),
    DESCRIBE_ENUM(SIOCDELDLCI),
    DESCRIBE_ENUM(SIOCDEVPRIVATE),
    DESCRIBE_ENUM(SIOCPROTOPRIVATE),
};

static struct enum_option sighows[] = {
	DESCRIBE_ENUM(SIG_BLOCK),
	DESCRIBE_ENUM(SIG_UNBLOCK),
	DESCRIBE_ENUM(SIG_SETMASK),
};

static struct enum_option madvises[] = {
	DESCRIBE_ENUM(MADV_NORMAL),
	DESCRIBE_ENUM(MADV_RANDOM),
	DESCRIBE_ENUM(MADV_SEQUENTIAL),
	DESCRIBE_ENUM(MADV_WILLNEED),
	DESCRIBE_ENUM(MADV_DONTNEED),
	DESCRIBE_ENUM(MADV_REMOVE),
	DESCRIBE_ENUM(MADV_DONTFORK),
	DESCRIBE_ENUM(MADV_DOFORK),
	DESCRIBE_ENUM(MADV_HWPOISON),
	DESCRIBE_ENUM(MADV_MERGEABLE),
	DESCRIBE_ENUM(MADV_UNMERGEABLE),
	// DESCRIBE_ENUM(MADV_SOFT_OFFLINE),
	DESCRIBE_ENUM(MADV_HUGEPAGE),
	DESCRIBE_ENUM(MADV_NOHUGEPAGE),
	DESCRIBE_ENUM(MADV_DONTDUMP),
	DESCRIBE_ENUM(MADV_DODUMP),
	DESCRIBE_ENUM(MADV_FREE),
	DESCRIBE_ENUM(MADV_WIPEONFORK),
	DESCRIBE_ENUM(MADV_KEEPONFORK),
};

static struct enum_option fcntls[] = {
	DESCRIBE_ENUM(F_DUPFD),
	DESCRIBE_ENUM(F_DUPFD_CLOEXEC),
	DESCRIBE_ENUM(F_GETFD),
	DESCRIBE_ENUM(F_SETFD),
	DESCRIBE_ENUM(F_GETFL),
	DESCRIBE_ENUM(F_SETFL),
	DESCRIBE_ENUM(F_SETLK),
	DESCRIBE_ENUM(F_SETLKW),
	DESCRIBE_ENUM(F_GETLK),
	DESCRIBE_ENUM(F_OFD_SETLK),
	DESCRIBE_ENUM(F_OFD_SETLKW),
	DESCRIBE_ENUM(F_OFD_GETLK),
	DESCRIBE_ENUM(F_GETOWN),
	DESCRIBE_ENUM(F_SETOWN),
	DESCRIBE_ENUM(F_GETOWN_EX),
	DESCRIBE_ENUM(F_SETOWN_EX),
	DESCRIBE_ENUM(F_GETSIG),
	DESCRIBE_ENUM(F_SETSIG),
	DESCRIBE_ENUM(F_SETLEASE),
	DESCRIBE_ENUM(F_GETLEASE),
	DESCRIBE_ENUM(F_NOTIFY),
	DESCRIBE_ENUM(F_SETPIPE_SZ),
	DESCRIBE_ENUM(F_GETPIPE_SZ),
	DESCRIBE_ENUM(F_ADD_SEALS),
	DESCRIBE_ENUM(F_GET_SEALS),
	DESCRIBE_ENUM(F_GET_RW_HINT),
	DESCRIBE_ENUM(F_SET_RW_HINT),
	DESCRIBE_ENUM(F_GET_FILE_RW_HINT),
	DESCRIBE_ENUM(F_SET_FILE_RW_HINT),
};

static struct enum_option rlimits[] = {
	DESCRIBE_ENUM(RLIMIT_AS),
	DESCRIBE_ENUM(RLIMIT_CORE),
	DESCRIBE_ENUM(RLIMIT_CPU),
	DESCRIBE_ENUM(RLIMIT_DATA),
	DESCRIBE_ENUM(RLIMIT_FSIZE),
	DESCRIBE_ENUM(RLIMIT_LOCKS),
	DESCRIBE_ENUM(RLIMIT_MEMLOCK),
	DESCRIBE_ENUM(RLIMIT_MSGQUEUE),
	DESCRIBE_ENUM(RLIMIT_NICE),
	DESCRIBE_ENUM(RLIMIT_NOFILE),
	DESCRIBE_ENUM(RLIMIT_NPROC),
	DESCRIBE_ENUM(RLIMIT_RSS),
	DESCRIBE_ENUM(RLIMIT_RTPRIO),
	DESCRIBE_ENUM(RLIMIT_RTTIME),
	DESCRIBE_ENUM(RLIMIT_SIGPENDING),
	DESCRIBE_ENUM(RLIMIT_STACK),
};

static struct enum_option socket_domains[] = {
	DESCRIBE_ENUM(AF_UNIX),
	DESCRIBE_ENUM(AF_LOCAL),
	DESCRIBE_ENUM(AF_INET),
	DESCRIBE_ENUM(AF_AX25),
	DESCRIBE_ENUM(AF_IPX),
	DESCRIBE_ENUM(AF_APPLETALK),
	DESCRIBE_ENUM(AF_X25),
	DESCRIBE_ENUM(AF_INET6),
	DESCRIBE_ENUM(AF_DECnet),
	DESCRIBE_ENUM(AF_KEY),
	DESCRIBE_ENUM(AF_NETLINK),
	DESCRIBE_ENUM(AF_PACKET),
	DESCRIBE_ENUM(AF_RDS),
	DESCRIBE_ENUM(AF_PPPOX),
	DESCRIBE_ENUM(AF_LLC),
	DESCRIBE_ENUM(AF_IB),
	DESCRIBE_ENUM(AF_MPLS),
	DESCRIBE_ENUM(AF_CAN),
	DESCRIBE_ENUM(AF_TIPC),
	DESCRIBE_ENUM(AF_BLUETOOTH),
	DESCRIBE_ENUM(AF_ALG),
	DESCRIBE_ENUM(AF_VSOCK),
	DESCRIBE_ENUM(AF_KCM),
	DESCRIBE_ENUM(AF_XDP),
};

static struct enum_option socket_types[] = {
	DESCRIBE_ENUM(SOCK_STREAM),
	DESCRIBE_ENUM(SOCK_DGRAM),
	DESCRIBE_ENUM(SOCK_SEQPACKET),
	DESCRIBE_ENUM(SOCK_RAW),
	DESCRIBE_ENUM(SOCK_RDM),
	DESCRIBE_ENUM(SOCK_PACKET),
};

static const char *socket_flags[64] = {
	DESCRIBE_FLAG(SOCK_NONBLOCK),
	DESCRIBE_FLAG(SOCK_CLOEXEC),
};

static struct enum_option clock_ids[] = {
	DESCRIBE_ENUM(CLOCK_REALTIME),
	DESCRIBE_ENUM(CLOCK_REALTIME_COARSE),
	DESCRIBE_ENUM(CLOCK_MONOTONIC),
	DESCRIBE_ENUM(CLOCK_MONOTONIC_COARSE),
	DESCRIBE_ENUM(CLOCK_MONOTONIC_RAW),
	DESCRIBE_ENUM(CLOCK_BOOTTIME),
	DESCRIBE_ENUM(CLOCK_PROCESS_CPUTIME_ID),
	DESCRIBE_ENUM(CLOCK_THREAD_CPUTIME_ID),
};

static struct enum_option socket_levels[] = {
	DESCRIBE_ENUM(SOL_SOCKET),
	DESCRIBE_ENUM(SOL_IP),
	DESCRIBE_ENUM(SOL_IPV6),
	DESCRIBE_ENUM(IPPROTO_TCP),
};

static struct enum_option socket_options[] = {
	DESCRIBE_ENUM(SO_DEBUG),
	DESCRIBE_ENUM(SO_REUSEADDR),
	DESCRIBE_ENUM(SO_KEEPALIVE),
	DESCRIBE_ENUM(SO_DONTROUTE),
	DESCRIBE_ENUM(SO_LINGER),
	DESCRIBE_ENUM(SO_BROADCAST),
	DESCRIBE_ENUM(SO_OOBINLINE),
	DESCRIBE_ENUM(SO_SNDBUF),
	DESCRIBE_ENUM(SO_SNDBUFFORCE),
	DESCRIBE_ENUM(SO_RCVBUF),
	DESCRIBE_ENUM(SO_TYPE),
	DESCRIBE_ENUM(SO_ERROR),
	DESCRIBE_ENUM(IP_RECVERR),
	DESCRIBE_ENUM(IPV6_RECVERR),
	DESCRIBE_ENUM(TCP_CONGESTION),
	DESCRIBE_ENUM(TCP_CORK),
	DESCRIBE_ENUM(TCP_DEFER_ACCEPT),
	DESCRIBE_ENUM(TCP_INFO),
	DESCRIBE_ENUM(TCP_KEEPCNT),
	DESCRIBE_ENUM(TCP_KEEPIDLE),
	DESCRIBE_ENUM(TCP_KEEPINTVL),
	DESCRIBE_ENUM(TCP_LINGER2),
	DESCRIBE_ENUM(TCP_MAXSEG),
	DESCRIBE_ENUM(TCP_NODELAY),
	DESCRIBE_ENUM(TCP_QUICKACK),
	DESCRIBE_ENUM(TCP_SYNCNT),
	DESCRIBE_ENUM(TCP_USER_TIMEOUT),
	DESCRIBE_ENUM(TCP_WINDOW_CLAMP),
	DESCRIBE_ENUM(TCP_FASTOPEN),
	DESCRIBE_ENUM(TCP_FASTOPEN_CONNECT),
};

static const char *msg_flags[64] = {
	DESCRIBE_FLAG(MSG_CMSG_CLOEXEC),
	DESCRIBE_FLAG(MSG_DONTWAIT),
	DESCRIBE_FLAG(MSG_ERRQUEUE),
	DESCRIBE_FLAG(MSG_OOB),
	DESCRIBE_FLAG(MSG_PEEK),
	DESCRIBE_FLAG(MSG_TRUNC),
	DESCRIBE_FLAG(MSG_WAITALL),
	DESCRIBE_FLAG(MSG_CONFIRM),
	DESCRIBE_FLAG(MSG_DONTROUTE),
	DESCRIBE_FLAG(MSG_EOR),
	DESCRIBE_FLAG(MSG_MORE),
	DESCRIBE_FLAG(MSG_NOSIGNAL),
};

static struct enum_option futex_operations[] = {
	DESCRIBE_ENUM(FUTEX_WAIT),
	DESCRIBE_ENUM(FUTEX_WAKE),
	DESCRIBE_ENUM(FUTEX_REQUEUE),
	DESCRIBE_ENUM(FUTEX_CMP_REQUEUE),
	DESCRIBE_ENUM(FUTEX_WAKE_OP),
	DESCRIBE_ENUM(FUTEX_WAIT_BITSET),
	DESCRIBE_ENUM(FUTEX_WAKE_BITSET),
	DESCRIBE_ENUM(FUTEX_LOCK_PI),
	DESCRIBE_ENUM(FUTEX_TRYLOCK_PI),
	DESCRIBE_ENUM(FUTEX_UNLOCK_PI),
	DESCRIBE_ENUM(FUTEX_CMP_REQUEUE_PI),
	DESCRIBE_ENUM(FUTEX_WAIT_REQUEUE_PI),
};

static const char *futex_flags[64] = {
	DESCRIBE_FLAG(FUTEX_PRIVATE_FLAG),
	DESCRIBE_FLAG(FUTEX_CLOCK_REALTIME),
};

static const char *signalfd_flags[64] = {
	DESCRIBE_FLAG(SFD_NONBLOCK),
	DESCRIBE_FLAG(SFD_CLOEXEC),
};

static const char *timerfd_flags[64] = {
	DESCRIBE_FLAG(TFD_NONBLOCK),
	DESCRIBE_FLAG(TFD_CLOEXEC),
};

static struct enum_option prctls[] = {
	DESCRIBE_ENUM(PR_CAP_AMBIENT),
	DESCRIBE_ENUM(PR_CAPBSET_READ),
	DESCRIBE_ENUM(PR_CAPBSET_DROP),
	DESCRIBE_ENUM(PR_SET_CHILD_SUBREAPER),
	DESCRIBE_ENUM(PR_GET_CHILD_SUBREAPER),
	DESCRIBE_ENUM(PR_SET_DUMPABLE),
	DESCRIBE_ENUM(PR_GET_DUMPABLE),
	// DESCRIBE_ENUM(PR_SET_IO_FLUSHER),
	// DESCRIBE_ENUM(PR_GET_IO_FLUSHER),
	DESCRIBE_ENUM(PR_SET_KEEPCAPS),
	DESCRIBE_ENUM(PR_GET_KEEPCAPS),
	DESCRIBE_ENUM(PR_MCE_KILL),
	DESCRIBE_ENUM(PR_MCE_KILL_GET),
	DESCRIBE_ENUM(PR_SET_MM),
	// DESCRIBE_ENUM(PR_SET_VMA),
	DESCRIBE_ENUM(PR_SET_NAME),
	DESCRIBE_ENUM(PR_GET_NAME),
	DESCRIBE_ENUM(PR_SET_NO_NEW_PRIVS),
	DESCRIBE_ENUM(PR_GET_NO_NEW_PRIVS),
	DESCRIBE_ENUM(PR_SET_PDEATHSIG),
	DESCRIBE_ENUM(PR_GET_PDEATHSIG),
	DESCRIBE_ENUM(PR_SET_PTRACER),
	DESCRIBE_ENUM(PR_SET_SECCOMP),
	DESCRIBE_ENUM(PR_GET_SECCOMP),
	DESCRIBE_ENUM(PR_SET_SECUREBITS),
	DESCRIBE_ENUM(PR_GET_SECUREBITS),
	DESCRIBE_ENUM(PR_GET_SPECULATION_CTRL),
	DESCRIBE_ENUM(PR_SET_SPECULATION_CTRL),
	// DESCRIBE_ENUM(PR_SET_SYSCALL_USER_DISPATCH),
	DESCRIBE_ENUM(PR_TASK_PERF_EVENTS_DISABLE),
	DESCRIBE_ENUM(PR_TASK_PERF_EVENTS_ENABLE),
	DESCRIBE_ENUM(PR_SET_THP_DISABLE),
	DESCRIBE_ENUM(PR_GET_THP_DISABLE),
	DESCRIBE_ENUM(PR_GET_TID_ADDRESS),
	DESCRIBE_ENUM(PR_SET_TIMERSLACK),
	DESCRIBE_ENUM(PR_GET_TIMERSLACK),
	DESCRIBE_ENUM(PR_SET_TIMING),
	DESCRIBE_ENUM(PR_GET_TIMING),
	DESCRIBE_ENUM(PR_SET_TSC),
	DESCRIBE_ENUM(PR_GET_TSC),
};

static const char *clone_flags[64] = {
	DESCRIBE_FLAG(CLONE_CHILD_CLEARTID),
	DESCRIBE_FLAG(CLONE_CHILD_SETTID),
	// DESCRIBE_FLAG(CLONE_CLEAR_SIGHAND),
	DESCRIBE_FLAG(CLONE_FILES),
	DESCRIBE_FLAG(CLONE_FS),
	DESCRIBE_FLAG(CLONE_IO),
	DESCRIBE_FLAG(CLONE_NEWCGROUP),
	DESCRIBE_FLAG(CLONE_NEWIPC),
	DESCRIBE_FLAG(CLONE_NEWNET),
	DESCRIBE_FLAG(CLONE_NEWNS),
	DESCRIBE_FLAG(CLONE_NEWPID),
	DESCRIBE_FLAG(CLONE_NEWUSER),
	DESCRIBE_FLAG(CLONE_NEWUTS),
	DESCRIBE_FLAG(CLONE_PARENT),
	DESCRIBE_FLAG(CLONE_PARENT_SETTID),
	DESCRIBE_FLAG(CLONE_PIDFD),
	DESCRIBE_FLAG(CLONE_PTRACE),
	DESCRIBE_FLAG(CLONE_SETTLS),
	DESCRIBE_FLAG(CLONE_SIGHAND),
	// DESCRIBE_FLAG(CLONE_STOPPED),
	DESCRIBE_FLAG(CLONE_SYSVSEM),
	DESCRIBE_FLAG(CLONE_THREAD),
	DESCRIBE_FLAG(CLONE_UNTRACED),
	DESCRIBE_FLAG(CLONE_VFORK),
	DESCRIBE_FLAG(CLONE_VM),
};

static const char *shm_flags[64] = {
	DESCRIBE_FLAG(IPC_CREAT),
	DESCRIBE_FLAG(IPC_EXCL),
	DESCRIBE_FLAG(SHM_HUGETLB),
	// DESCRIBE_FLAG(SHM_HUGE_2MB),
	// DESCRIBE_FLAG(SHM_HUGE_1GB),
	DESCRIBE_FLAG(SHM_NORESERVE),
};

__attribute__((nonnull(1)))
static char *copy_register_state_description_simple(const struct loader_context *context, struct register_state reg)
{
	if (register_is_exactly_known(&reg)) {
		return copy_address_details(context, (const void *)reg.value, false);
	}
	char *min = copy_address_details(context, (const void *)reg.value, false);
	size_t min_size = fs_strlen(min);
	char *max = copy_address_details(context, (const void *)reg.max, false);
	size_t max_size = fs_strlen(max);
	char *result = malloc(min_size + max_size + 2);
	fs_memcpy(result, min, min_size);
	result[min_size] = '-';
	fs_memcpy(&result[min_size+1], max, max_size + 1);
	free(min);
	free(max);
	return result;
}

static char *copy_enum_flags_description(const struct loader_context *context, struct register_state state, const struct enum_option *options, size_t sizeof_options, const char *flags[64], bool always_enum)
{
	if (!register_is_exactly_known(&state)) {
		if (state.value == 0) {
			if (state.max == ~(uintptr_t)0) {
				char *result = malloc(sizeof("any"));
				memcpy(result, "any", sizeof("any"));
				return result;
			}
			if (state.max == 0xffffffff) {
				char *result = malloc(sizeof("any u32"));
				memcpy(result, "any u32", sizeof("any u32"));
				return result;
			}
			if (state.max == 0xffff) {
				char *result = malloc(sizeof("any u16"));
				memcpy(result, "any u16", sizeof("any u16"));
				return result;
			}
			if (state.max == 0xff) {
				char *result = malloc(sizeof("any u8"));
				memcpy(result, "any u8", sizeof("any u8"));
				return result;
			}
		}
		return copy_register_state_description_simple(context, state);
	}
	if (flags == NULL) {
		for (size_t i = 0; i < sizeof_options / sizeof(*options); i++) {
			if (state.value == options[i].value) {
				return strdup(options[i].description);
			}
		}
		return copy_register_state_description_simple(context, state);
	}
	// calculate length
	size_t length = 0;
	uintptr_t remaining = 0;
	for_each_bit(state.value, bit, i) {
		if (flags[i] != NULL) {
			length += fs_strlen(flags[i]) + 1;
		} else {
			remaining |= bit;
		}
	}
	const char *suffix = NULL;
	size_t suffix_len = 0;
	if (length == 0 || remaining != 0 || always_enum) {
		for (size_t i = 0; i < sizeof_options / sizeof(*options); i++) {
			if (remaining == options[i].value) {
				suffix = options[i].description;
				suffix_len = fs_strlen(suffix);
				length += suffix_len + 1;
				break;
			}
		}
		char num_buf[64];
		if (suffix == NULL && (length == 0 || remaining != 0)) {
			suffix = num_buf;
			suffix_len = remaining < PAGE_SIZE ? fs_utoa(remaining, num_buf) : fs_utoah(remaining, num_buf);
			length += suffix_len + 1;
		}
	}
	// allocate buffer
	char *result = malloc(length);
	// fill buffer
	char *next = result;
	if (suffix_len != 0) {
		fs_memcpy(next, suffix, suffix_len);
		next[suffix_len] = '|';
		next += suffix_len + 1;
	}
	for_each_bit(state.value, bit, i) {
		if (flags[i] != NULL) {
			next = fs_strcpy(next, flags[i]);
			*next++ = '|';
		}
	}
	next--;
	*next = '\0';
	return result;
}

static inline size_t format_octal(uintptr_t value, char buffer[])
{
	buffer[0] = '0';
	if (value == 0) {
		buffer[1] = '\0';
		return 1;
	}
	size_t i = 1;
	while (value != 0) {
		buffer[i++] = "0123456789"[(unsigned char)value & 0x7];
		value = value >> 3;
	}
	buffer[i] = '\0';
	fs_reverse(&buffer[1], i-1);
	return i+1;
}

static char *copy_mode_description(struct register_state reg)
{
	if (reg.value == 0) {
		if (reg.max == ~(uintptr_t)0) {
			char *result = malloc(sizeof("any"));
			memcpy(result, "any", sizeof("any"));
			return result;
		}
		if (reg.max == 0xffffffff) {
			char *result = malloc(sizeof("any u32"));
			memcpy(result, "any u32", sizeof("any u32"));
			return result;
		}
		if (reg.max == 0xffff) {
			char *result = malloc(sizeof("any u16"));
			memcpy(result, "any u16", sizeof("any u16"));
			return result;
		}
		if (reg.max == 0xff) {
			char *result = malloc(sizeof("any u8"));
			memcpy(result, "any u8", sizeof("any u8"));
			return result;
		}
	}
	char buf[64];
	size_t size;
	if (register_is_exactly_known(&reg)) {
		size = format_octal(reg.value, buf);
	} else {
		size_t prefix_size = format_octal(reg.value, buf);
		buf[prefix_size] = '-';
		size_t suffix_size = format_octal(reg.max, &buf[prefix_size+1]);
		size = prefix_size + 1 + suffix_size;
	}
	char *result = malloc(size+1);
	memcpy(result, buf, size+1);
	return result;
}


__attribute__((unused))
__attribute__((nonnull(1, 2, 4)))
char *copy_call_description(const struct loader_context *context, const char *name, struct registers registers, const int *register_indexes, struct syscall_info info, bool include_symbol)
{
	int argc = info.attributes & SYSCALL_ARGC_MASK;
	size_t name_len = fs_strlen(name);
	size_t len = name_len + 3; // name + '(' + ... + ')' + '\0'
	char *args[9];
	size_t arg_len[9];
	for (int i = 0; i < argc; i++) {
		if (i != 0) {
			len += 2; // ", "
		}
		int reg = register_indexes[i];
		if (include_symbol) {
			switch (info.arguments[i] & SYSCALL_ARG_TYPE_MASK) {
				case SYSCALL_ARG_IS_PROT:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], prots, sizeof(prots), prot_flags, false);
					break;
				case SYSCALL_ARG_IS_MAP_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], maps, sizeof(maps), map_flags, true);
					break;
				case SYSCALL_ARG_IS_REMAP_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], NULL, 0, remap_flags, false);
					break;
				case SYSCALL_ARG_IS_OPEN_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], opens, sizeof(opens), open_flags, true);
					break;
				case SYSCALL_ARG_IS_SIGNUM:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], signums, sizeof(signums), NULL, false);
					break;
				case SYSCALL_ARG_IS_IOCTL:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], ioctls, sizeof(ioctls), NULL, false);
					break;
				case SYSCALL_ARG_IS_SIGHOW:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], sighows, sizeof(sighows), NULL, false);
					break;
				case SYSCALL_ARG_IS_MADVISE:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], madvises, sizeof(madvises), NULL, false);
					break;
				case SYSCALL_ARG_IS_FCNTL:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], fcntls, sizeof(fcntls), NULL, false);
					break;
				case SYSCALL_ARG_IS_RLIMIT:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], rlimits, sizeof(rlimits), NULL, false);
					break;
				case SYSCALL_ARG_IS_SOCKET_DOMAIN:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], socket_domains, sizeof(socket_domains), NULL, false);
					break;
				case SYSCALL_ARG_IS_SOCKET_TYPE:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], socket_types, sizeof(socket_types), socket_flags, true);
					break;
				case SYSCALL_ARG_IS_CLOCK_ID:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], clock_ids, sizeof(clock_ids), NULL, false);
					break;
				case SYSCALL_ARG_IS_SOCKET_LEVEL:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], socket_levels, sizeof(socket_levels), NULL, false);
					break;
				case SYSCALL_ARG_IS_SOCKET_OPTION:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], socket_options, sizeof(socket_options), NULL, false);
					break;
				case SYSCALL_ARG_IS_ACCESS_MODE:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], access_modes, sizeof(access_modes), access_mode_flags, false);
					break;
				case SYSCALL_ARG_IS_ACCESSAT_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], NULL, 0, accessat_flags, false);
					break;
				case SYSCALL_ARG_IS_REMOVEAT_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], NULL, 0, removeat_flags, false);
					break;
				case SYSCALL_ARG_IS_MSYNC_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], NULL, 0, msync_flags, false);
					break;
				case SYSCALL_ARG_IS_OFLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], NULL, 0, open_flags, false);
					break;
				case SYSCALL_ARG_IS_MSG_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], NULL, 0, msg_flags, false);
					break;
				case SYSCALL_ARG_IS_SHUTDOWN_HOW:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], shutdown_hows, sizeof(shutdown_hows), NULL, false);
					break;
				case SYSCALL_ARG_IS_FUTEX_OP:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], futex_operations, sizeof(futex_operations), futex_flags, true);
					break;
				case SYSCALL_ARG_IS_SIGNALFD_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], NULL, 0, signalfd_flags, false);
					break;
				case SYSCALL_ARG_IS_TIMERFD_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], NULL, 0, timerfd_flags, false);
					break;
				case SYSCALL_ARG_IS_SOCKET_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], NULL, 0, socket_flags, false);
					break;
				case SYSCALL_ARG_IS_PRCTL:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], prctls, sizeof(prctls), NULL, false);
					break;
				case SYSCALL_ARG_IS_CLONEFLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], signums, sizeof(signums), clone_flags, true);
					break;
				case SYSCALL_ARG_IS_SHM_FLAGS:
					args[i] = copy_enum_flags_description(context, registers.registers[reg], NULL, 0, shm_flags, true);
					break;
				case SYSCALL_ARG_IS_PID:
					if (context->pid != 0 && register_is_exactly_known(&registers.registers[reg]) && registers.registers[reg].value == (uintptr_t)context->pid) {
						args[i] = strdup("getpid()");
					} else {
						args[i] = copy_register_state_description(context, registers.registers[reg]);
					}
					break;
				case SYSCALL_ARG_IS_MODE:
				case SYSCALL_ARG_IS_MODEFLAGS:
					args[i] = copy_mode_description(registers.registers[reg]);
					break;
				case SYSCALL_ARG_IS_SOCKET_PROTOCOL:
				default:
					args[i] = copy_register_state_description(context, registers.registers[reg]);
					break;
			}
		} else {
			args[i] = copy_register_state_description_simple(context, registers.registers[reg]);
		}
		arg_len[i] = fs_strlen(args[i]);
		len += arg_len[i];
	}
	char *result = malloc(len);
	fs_memcpy(result, name, name_len);
	size_t pos = name_len;
	result[pos++] = '(';
	for (int i = 0; i < argc; i++) {
		if (i != 0) {
			result[pos++] = ',';
			result[pos++] = ' ';
		}
		fs_memcpy(&result[pos], args[i], arg_len[i]);
		free(args[i]);
		pos += arg_len[i];
	}
	result[pos++] = ')';
	result[pos++] = '\0';
	return result;
}
