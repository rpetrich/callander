#define _GNU_SOURCE
#define _XOPEN_SOURCE
#include "callander_print.h"

#include <sys/mount.h>
#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/fsmap.h>
#include <linux/kd.h>
#include <linux/memfd.h>
#include <linux/module.h>
#include <linux/nsfs.h>
#include <linux/perf_event.h>
#include <linux/seccomp.h>
#include <linux/socket.h>
#include <linux/tiocl.h>
#include <linux/userfaultfd.h>
#include <linux/vt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/random.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>

static inline char *strdup_fixed(const char *str, size_t size)
{
	char *buf = malloc(size);
	memcpy(buf, str, size);
	return buf;
}

#define strdup(x) _Generic((x), char *: strdup(x), const char*: strdup(x), const char[sizeof(x)]: strdup_fixed(x, sizeof(x)), char[sizeof(x)]: strdup_fixed(x, sizeof(x)))

__attribute__((nonnull(1)))
char *copy_register_state_description(const struct loader_context *context, struct register_state reg)
{
	if (register_is_exactly_known(&reg)) {
		if (reg.value == ~(uintptr_t)0) {
			return strdup("-1");
		}
		if (reg.value == 0xffffffff) {
			return strdup("-1 as u32");
		}
		if (reg.value == 0x7fffffff) {
			return strdup("INT_MAX");
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
			return strdup("non-NULL");
		}
		if (reg.value == 0) {
			if (reg.max == 0xffffffff) {
				return strdup("any u32");
			}
			if (reg.max == 0x7fffffff) {
				return strdup("0-INT_MAX");
			}
			if (reg.max == 0xffff) {
				return strdup("any u16");
			}
			if (reg.max == 0xff) {
				return strdup("any u8");
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
	return strdup("any");
}

struct enum_option {
	uintptr_t value;
	const char *description;
};

#define DESCRIBE_ENUM(x) { .value = x, .description = #x }

#define DESCRIBE_FLAG(X) [(__builtin_popcount(X) == 1 ? (unsigned) (8*sizeof (unsigned long long) - __builtin_clzll((X)) - 1) : (unsigned)-1)] = #X

struct enum_option file_descriptors[] = {
	DESCRIBE_ENUM(STDIN_FILENO),
	DESCRIBE_ENUM(STDOUT_FILENO),
	DESCRIBE_ENUM(STDERR_FILENO),
	DESCRIBE_ENUM(AT_FDCWD),
	{ .value = (uint32_t)AT_FDCWD, .description = "AT_FDCWD" },
	{ .value = -1, .description = "-1" },
	{ .value = (uint32_t)-1, .description = "-1 as u32" },
};

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
#ifdef __O_SYNC
#undef __O_SYNC
#endif
#define __O_SYNC	04000000
#ifdef __O_TMPFILE
#undef __O_TMPFILE
#endif
#define __O_TMPFILE	020000000

static struct enum_option opens[] = {
	DESCRIBE_ENUM(O_RDONLY),
	DESCRIBE_ENUM(O_WRONLY),
	DESCRIBE_ENUM(O_RDWR),
	DESCRIBE_ENUM(O_ACCMODE),
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
	DESCRIBE_FLAG(O_NOCTTY),
	DESCRIBE_FLAG(O_NOFOLLOW),
	DESCRIBE_FLAG(O_NONBLOCK),
	DESCRIBE_FLAG(O_PATH),
	DESCRIBE_FLAG(__O_SYNC),
	DESCRIBE_FLAG(O_TMPFILE),
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

#define SIGTIMER 32
// #define SIGCANCEL 33
#define SIGSYNCCALL 34

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
	DESCRIBE_ENUM(SIGTIMER),
	DESCRIBE_ENUM(SIGSYNCCALL),
};

#ifndef UFFDIO_WRITEPROTECT
#define _UFFDIO_WRITEPROTECT (0x06)
#define UFFDIO_WRITEPROTECT _IOWR(UFFDIO, _UFFDIO_WRITEPROTECT, void)
#endif
#ifndef UFFDIO_CONTINUE
#define _UFFDIO_CONTINUE (0x07)
#define UFFDIO_CONTINUE  _IOWR(UFFDIO, _UFFDIO_CONTINUE, void)
#endif

#ifndef SECCOMP_IOCTL_NOTIF_ADDFD
#define SECCOMP_IOCTL_NOTIF_ADDFD SECCOMP_IOW(3, void)
#endif

static struct enum_option ioctls[] = {
	// ioctl_tty
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
    // ioctl_userfaultfd
    DESCRIBE_ENUM(UFFDIO_API),
    DESCRIBE_ENUM(UFFDIO_REGISTER),
    DESCRIBE_ENUM(UFFDIO_UNREGISTER),
    DESCRIBE_ENUM(UFFDIO_WAKE),
    DESCRIBE_ENUM(UFFDIO_COPY),
    DESCRIBE_ENUM(UFFDIO_ZEROPAGE),
    DESCRIBE_ENUM(UFFDIO_WRITEPROTECT),
    DESCRIBE_ENUM(UFFDIO_CONTINUE),
    // ioctl_console
    DESCRIBE_ENUM(KDGETLED),
    DESCRIBE_ENUM(KDSETLED),
    DESCRIBE_ENUM(KDGKBLED),
    DESCRIBE_ENUM(KDSKBLED),
    DESCRIBE_ENUM(KDGKBTYPE),
    DESCRIBE_ENUM(KDADDIO),
    DESCRIBE_ENUM(KDDELIO),
    DESCRIBE_ENUM(KDENABIO),
    DESCRIBE_ENUM(KDDISABIO),
    DESCRIBE_ENUM(KDSETMODE),
    DESCRIBE_ENUM(KDGETMODE),
    DESCRIBE_ENUM(KDMKTONE),
    DESCRIBE_ENUM(KIOCSOUND),
    DESCRIBE_ENUM(GIO_CMAP),
    DESCRIBE_ENUM(PIO_CMAP),
    DESCRIBE_ENUM(GIO_FONT),
    DESCRIBE_ENUM(GIO_FONTX),
    DESCRIBE_ENUM(PIO_FONT),
    DESCRIBE_ENUM(PIO_FONTX),
    DESCRIBE_ENUM(PIO_FONTRESET),
    DESCRIBE_ENUM(GIO_SCRNMAP),
    DESCRIBE_ENUM(GIO_UNISCRNMAP),
    DESCRIBE_ENUM(PIO_SCRNMAP),
    DESCRIBE_ENUM(PIO_UNISCRNMAP),
    DESCRIBE_ENUM(GIO_UNIMAP),
    DESCRIBE_ENUM(PIO_UNIMAP),
    DESCRIBE_ENUM(PIO_UNIMAPCLR),
    DESCRIBE_ENUM(KDGKBMODE),
    DESCRIBE_ENUM(KDSKBMODE),
    DESCRIBE_ENUM(KDGKBMETA),
    DESCRIBE_ENUM(KDSKBMETA),
    DESCRIBE_ENUM(KDGKBENT),
    DESCRIBE_ENUM(KDSKBENT),
    DESCRIBE_ENUM(KDGKBSENT),
    DESCRIBE_ENUM(KDSKBSENT),
    DESCRIBE_ENUM(KDGKBDIACR),
    DESCRIBE_ENUM(KDGETKEYCODE),
    DESCRIBE_ENUM(KDSETKEYCODE),
    DESCRIBE_ENUM(KDSIGACCEPT),
    DESCRIBE_ENUM(VT_OPENQRY),
    DESCRIBE_ENUM(VT_GETMODE),
    DESCRIBE_ENUM(VT_SETMODE),
    DESCRIBE_ENUM(VT_GETSTATE),
    DESCRIBE_ENUM(VT_RELDISP),
    DESCRIBE_ENUM(VT_ACTIVATE),
    DESCRIBE_ENUM(VT_WAITACTIVE),
    DESCRIBE_ENUM(VT_DISALLOCATE),
    DESCRIBE_ENUM(VT_RESIZE),
    DESCRIBE_ENUM(VT_RESIZEX),
    // ioctl_ficlone
    DESCRIBE_ENUM(FICLONERANGE),
    DESCRIBE_ENUM(FICLONE),
    // ioctl_fideduperange
    DESCRIBE_ENUM(FIDEDUPERANGE),
    // ioctl_fslabel
    DESCRIBE_ENUM(FS_IOC_GETFSLABEL),
    DESCRIBE_ENUM(FS_IOC_SETFSLABEL),
    // ioctl_getfsmap
    DESCRIBE_ENUM(FS_IOC_GETFSMAP),
    // ioctl_iflags
    DESCRIBE_ENUM(FS_IOC_GETFLAGS),
    DESCRIBE_ENUM(FS_IOC_SETFLAGS),
    // ioctl_ns
    DESCRIBE_ENUM(NS_GET_USERNS),
    DESCRIBE_ENUM(NS_GET_PARENT),
    // seccomp_unotify
    DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_RECV),
    DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_SEND),
    DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_ID_VALID),
    DESCRIBE_ENUM(SECCOMP_IOCTL_NOTIF_ADDFD),
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

#define MSG_PROBE 0x10
#define MSG_CMSG_COMPAT 0x80000000

static const char *msg_flags[64] = {
	DESCRIBE_FLAG(MSG_OOB),
	DESCRIBE_FLAG(MSG_PEEK),
	DESCRIBE_FLAG(MSG_DONTROUTE),
	DESCRIBE_FLAG(MSG_CTRUNC),
	DESCRIBE_FLAG(MSG_PROBE),
	DESCRIBE_FLAG(MSG_TRUNC),
	DESCRIBE_FLAG(MSG_DONTWAIT),
	DESCRIBE_FLAG(MSG_EOR),
	DESCRIBE_FLAG(MSG_WAITALL),
	DESCRIBE_FLAG(MSG_FIN),
	DESCRIBE_FLAG(MSG_SYN),
	DESCRIBE_FLAG(MSG_CONFIRM),
	DESCRIBE_FLAG(MSG_RST),
	DESCRIBE_FLAG(MSG_ERRQUEUE),
	DESCRIBE_FLAG(MSG_NOSIGNAL),
	DESCRIBE_FLAG(MSG_MORE),
	DESCRIBE_FLAG(MSG_WAITFORONE),
	// DESCRIBE_FLAG(MSG_SENDPAGE_NOPOLICY),
	DESCRIBE_FLAG(MSG_BATCH),
	// DESCRIBE_FLAG(MSG_NO_SHARED_FRAGS),
	// DESCRIBE_FLAG(MSG_SENDPAGE_DECRYPTED),
	DESCRIBE_FLAG(MSG_ZEROCOPY),
	// DESCRIBE_FLAG(MSG_SPLICE_PAGES),
	DESCRIBE_FLAG(MSG_FASTOPEN),
	DESCRIBE_FLAG(MSG_CMSG_CLOEXEC),
	DESCRIBE_FLAG(MSG_CMSG_COMPAT),
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

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

static struct enum_option wait_idtypes[] = {
	DESCRIBE_ENUM(P_PID),
	DESCRIBE_ENUM(P_PIDFD),
	DESCRIBE_ENUM(P_PGID),
	DESCRIBE_ENUM(P_ALL),
};

static struct enum_option seccomp_operations[] = {
	DESCRIBE_ENUM(SECCOMP_SET_MODE_STRICT),
	DESCRIBE_ENUM(SECCOMP_SET_MODE_FILTER),
	DESCRIBE_ENUM(SECCOMP_GET_ACTION_AVAIL),
};

static struct enum_option bpf_commands[] = {
	DESCRIBE_ENUM(BPF_MAP_CREATE),
	DESCRIBE_ENUM(BPF_MAP_LOOKUP_ELEM),
	DESCRIBE_ENUM(BPF_MAP_UPDATE_ELEM),
	DESCRIBE_ENUM(BPF_MAP_DELETE_ELEM),
	DESCRIBE_ENUM(BPF_MAP_GET_NEXT_KEY),
	DESCRIBE_ENUM(BPF_PROG_LOAD),
};

static struct enum_option membarrier_commands[] = {
	DESCRIBE_ENUM(MEMBARRIER_CMD_QUERY),
	DESCRIBE_ENUM(MEMBARRIER_CMD_GLOBAL),
	DESCRIBE_ENUM(MEMBARRIER_CMD_GLOBAL_EXPEDITED),
	DESCRIBE_ENUM(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED),
	DESCRIBE_ENUM(MEMBARRIER_CMD_PRIVATE_EXPEDITED),
	DESCRIBE_ENUM(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED),
	DESCRIBE_ENUM(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE),
	DESCRIBE_ENUM(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE),
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

static struct enum_option flock_operations[] = {
	DESCRIBE_ENUM(LOCK_SH),
	DESCRIBE_ENUM(LOCK_EX),
	DESCRIBE_ENUM(LOCK_UN),
	DESCRIBE_ENUM(LOCK_MAND),
};

static const char *flock_flags[] = {
	DESCRIBE_FLAG(LOCK_NB),
	DESCRIBE_FLAG(LOCK_READ),
	DESCRIBE_FLAG(LOCK_WRITE),
};

static struct enum_option itimer_whiches[] = {
	DESCRIBE_ENUM(ITIMER_REAL),
	DESCRIBE_ENUM(ITIMER_VIRTUAL),
	DESCRIBE_ENUM(ITIMER_PROF),
};

static struct enum_option seek_whences[] = {
	DESCRIBE_ENUM(SEEK_SET),
	DESCRIBE_ENUM(SEEK_CUR),
	DESCRIBE_ENUM(SEEK_END),
	DESCRIBE_ENUM(SEEK_DATA),
	DESCRIBE_ENUM(SEEK_HOLE),
};

static struct enum_option shmctl_commands[] = {
	DESCRIBE_ENUM(IPC_STAT),
	DESCRIBE_ENUM(IPC_SET),
	DESCRIBE_ENUM(IPC_RMID),
	DESCRIBE_ENUM(IPC_INFO),
	DESCRIBE_ENUM(SHM_INFO),
	DESCRIBE_ENUM(SHM_STAT),
	DESCRIBE_ENUM(SHM_STAT_ANY),
	DESCRIBE_ENUM(SHM_LOCK),
	DESCRIBE_ENUM(SHM_UNLOCK),
};

static struct enum_option semctl_commands[] = {
	DESCRIBE_ENUM(IPC_STAT),
	DESCRIBE_ENUM(IPC_SET),
	DESCRIBE_ENUM(IPC_RMID),
	DESCRIBE_ENUM(IPC_INFO),
	DESCRIBE_ENUM(SEM_INFO),
	DESCRIBE_ENUM(SEM_STAT),
	DESCRIBE_ENUM(SEM_STAT_ANY),
	DESCRIBE_ENUM(GETALL),
	DESCRIBE_ENUM(GETNCNT),
	DESCRIBE_ENUM(GETPID),
	DESCRIBE_ENUM(GETVAL),
	DESCRIBE_ENUM(GETZCNT),
	DESCRIBE_ENUM(SETALL),
	DESCRIBE_ENUM(SETVAL),
};

static struct enum_option ptrace_requests[] = {
	DESCRIBE_ENUM(PTRACE_TRACEME),
	DESCRIBE_ENUM(PTRACE_PEEKTEXT),
	DESCRIBE_ENUM(PTRACE_PEEKDATA),
	DESCRIBE_ENUM(PTRACE_PEEKUSER),
	DESCRIBE_ENUM(PTRACE_POKETEXT),
	DESCRIBE_ENUM(PTRACE_POKEDATA),
	DESCRIBE_ENUM(PTRACE_POKEUSER),
	DESCRIBE_ENUM(PTRACE_GETREGS),
	DESCRIBE_ENUM(PTRACE_GETFPREGS),
	DESCRIBE_ENUM(PTRACE_GETREGSET),
	DESCRIBE_ENUM(PTRACE_SETREGS),
	DESCRIBE_ENUM(PTRACE_SETFPREGS),
	DESCRIBE_ENUM(PTRACE_SETREGSET),
	DESCRIBE_ENUM(PTRACE_GETSIGINFO),
	DESCRIBE_ENUM(PTRACE_SETSIGINFO),
	DESCRIBE_ENUM(PTRACE_PEEKSIGINFO),
	DESCRIBE_ENUM(PTRACE_GETSIGMASK),
	DESCRIBE_ENUM(PTRACE_SETSIGMASK),
	DESCRIBE_ENUM(PTRACE_SETOPTIONS),
	DESCRIBE_ENUM(PTRACE_GETEVENTMSG),
	DESCRIBE_ENUM(PTRACE_CONT),
	DESCRIBE_ENUM(PTRACE_SYSCALL),
	DESCRIBE_ENUM(PTRACE_SINGLESTEP),
	DESCRIBE_ENUM(PTRACE_SYSEMU),
	DESCRIBE_ENUM(PTRACE_SYSEMU_SINGLESTEP),
	DESCRIBE_ENUM(PTRACE_LISTEN),
	DESCRIBE_ENUM(PTRACE_KILL),
	DESCRIBE_ENUM(PTRACE_INTERRUPT),
	DESCRIBE_ENUM(PTRACE_ATTACH),
	DESCRIBE_ENUM(PTRACE_SEIZE),
	DESCRIBE_ENUM(PTRACE_SECCOMP_GET_FILTER),
	DESCRIBE_ENUM(PTRACE_DETACH),
	DESCRIBE_ENUM(PTRACE_GET_THREAD_AREA),
	DESCRIBE_ENUM(PTRACE_SET_THREAD_AREA),
	DESCRIBE_ENUM(PTRACE_GET_SYSCALL_INFO),
};

static const char *clone_flags[64] = {
	DESCRIBE_FLAG(CLONE_CHILD_CLEARTID),
	DESCRIBE_FLAG(CLONE_CHILD_SETTID),
	// DESCRIBE_FLAG(CLONE_CLEAR_SIGHAND), // clone3 only
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
	DESCRIBE_FLAG(CLONE_SYSVSEM),
	DESCRIBE_FLAG(CLONE_THREAD),
	DESCRIBE_FLAG(CLONE_UNTRACED),
	DESCRIBE_FLAG(CLONE_VFORK),
	DESCRIBE_FLAG(CLONE_VM),
	DESCRIBE_FLAG(CLONE_DETACHED),
};

#define CLONE_NEWTIME 0x00000080

static const char *unshare_flags[64] = {
	DESCRIBE_FLAG(CLONE_CHILD_CLEARTID),
	DESCRIBE_FLAG(CLONE_CHILD_SETTID),
	// DESCRIBE_FLAG(CLONE_CLEAR_SIGHAND), // clone3 only
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
	DESCRIBE_FLAG(CLONE_NEWTIME),
	DESCRIBE_FLAG(CLONE_PARENT),
	DESCRIBE_FLAG(CLONE_PARENT_SETTID),
	DESCRIBE_FLAG(CLONE_PIDFD),
	DESCRIBE_FLAG(CLONE_PTRACE),
	DESCRIBE_FLAG(CLONE_SETTLS),
	DESCRIBE_FLAG(CLONE_SIGHAND),
	DESCRIBE_FLAG(CLONE_SYSVSEM),
	DESCRIBE_FLAG(CLONE_THREAD),
	DESCRIBE_FLAG(CLONE_UNTRACED),
	DESCRIBE_FLAG(CLONE_VFORK),
	DESCRIBE_FLAG(CLONE_VM),
	DESCRIBE_FLAG(CLONE_DETACHED),
};

// #define SHM_HUGE_64KB	HUGETLB_FLAG_ENCODE_64KB
// #define SHM_HUGE_512KB	HUGETLB_FLAG_ENCODE_512KB
// #define SHM_HUGE_1MB	HUGETLB_FLAG_ENCODE_1MB
// #define SHM_HUGE_2MB	HUGETLB_FLAG_ENCODE_2MB
// #define SHM_HUGE_8MB	HUGETLB_FLAG_ENCODE_8MB
// #define SHM_HUGE_16MB	HUGETLB_FLAG_ENCODE_16MB
// #define SHM_HUGE_32MB	HUGETLB_FLAG_ENCODE_32MB
// #define SHM_HUGE_256MB	HUGETLB_FLAG_ENCODE_256MB
// #define SHM_HUGE_512MB	HUGETLB_FLAG_ENCODE_512MB
// #define SHM_HUGE_1GB	HUGETLB_FLAG_ENCODE_1GB
// #define SHM_HUGE_2GB	HUGETLB_FLAG_ENCODE_2GB
// #define SHM_HUGE_16GB	HUGETLB_FLAG_ENCODE_16GB

static const char *shm_flags[64] = {
	DESCRIBE_FLAG(IPC_CREAT),
	DESCRIBE_FLAG(IPC_EXCL),
	DESCRIBE_FLAG(SHM_HUGETLB),
	// DESCRIBE_FLAG(SHM_HUGE_2MB),
	// DESCRIBE_FLAG(SHM_HUGE_1GB),
	DESCRIBE_FLAG(SHM_R),
	DESCRIBE_FLAG(SHM_W),
	DESCRIBE_FLAG(SHM_NORESERVE),
};

static const char *sem_flags[64] = {
	DESCRIBE_FLAG(IPC_CREAT),
	DESCRIBE_FLAG(IPC_EXCL),
	DESCRIBE_FLAG(SEM_UNDO),
};

static const char *eventfd_flags[64] = {
	DESCRIBE_FLAG(EFD_CLOEXEC),
	DESCRIBE_FLAG(EFD_NONBLOCK),
	DESCRIBE_FLAG(EFD_SEMAPHORE),
};

static const char *epoll_flags[64] = {
	DESCRIBE_FLAG(EPOLL_CLOEXEC),
};

static const char *xattr_flags[64] = {
	DESCRIBE_FLAG(XATTR_CREATE),
	DESCRIBE_FLAG(XATTR_REPLACE),
};

static const char *timer_flags[64] = {
	DESCRIBE_FLAG(TIMER_ABSTIME),
};

static const char *wait_flags[64] = {
	DESCRIBE_FLAG(WNOHANG),
	DESCRIBE_FLAG(WUNTRACED),
	DESCRIBE_FLAG(WCONTINUED),
	DESCRIBE_FLAG(WEXITED),
	DESCRIBE_FLAG(WNOWAIT),
	DESCRIBE_FLAG(__WNOTHREAD),
	DESCRIBE_FLAG(__WALL),
	DESCRIBE_FLAG(__WCLONE),
};

static const char *inotify_event_flags[64] = {
	DESCRIBE_FLAG(IN_ACCESS),
	DESCRIBE_FLAG(IN_ATTRIB),
	DESCRIBE_FLAG(IN_CLOSE_WRITE),
	DESCRIBE_FLAG(IN_CLOSE_NOWRITE),
	DESCRIBE_FLAG(IN_CREATE),
	DESCRIBE_FLAG(IN_DELETE),
	DESCRIBE_FLAG(IN_DELETE_SELF),
	DESCRIBE_FLAG(IN_MODIFY),
	DESCRIBE_FLAG(IN_MOVE_SELF),
	DESCRIBE_FLAG(IN_MOVED_FROM),
	DESCRIBE_FLAG(IN_MOVED_TO),
	DESCRIBE_FLAG(IN_OPEN),
	DESCRIBE_FLAG(IN_DONT_FOLLOW),
	DESCRIBE_FLAG(IN_EXCL_UNLINK),
	DESCRIBE_FLAG(IN_MASK_ADD),
	DESCRIBE_FLAG(IN_ONESHOT),
	DESCRIBE_FLAG(IN_ONLYDIR),
	DESCRIBE_FLAG(IN_MASK_CREATE),
	DESCRIBE_FLAG(IN_IGNORED),
	DESCRIBE_FLAG(IN_ISDIR),
	DESCRIBE_FLAG(IN_Q_OVERFLOW),
	DESCRIBE_FLAG(IN_UNMOUNT),
};

static const char *inotify_init_flags[64] = {
	DESCRIBE_FLAG(IN_NONBLOCK),
	DESCRIBE_FLAG(IN_CLOEXEC),
};

static const char *memfd_flags[64] = {
	DESCRIBE_FLAG(MFD_CLOEXEC),
	DESCRIBE_FLAG(MFD_ALLOW_SEALING),
	DESCRIBE_FLAG(MFD_HUGETLB),
	// DESCRIBE_FLAG(MFD_HUGE_2MB),
	// DESCRIBE_FLAG(MFD_HUGE_1GB),
};

#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif

static const char *userfaultfd_flags[64] = {
	DESCRIBE_FLAG(O_CLOEXEC),
	DESCRIBE_FLAG(O_NONBLOCK),
	DESCRIBE_FLAG(UFFD_USER_MODE_ONLY),
};

static const char *mlockall_flags[64] = {
	DESCRIBE_FLAG(MCL_CURRENT),
	DESCRIBE_FLAG(MCL_FUTURE),
};

static const char *umount_flags[64] = {
	DESCRIBE_FLAG(MNT_FORCE),
	DESCRIBE_FLAG(MNT_DETACH),
	DESCRIBE_FLAG(MNT_EXPIRE),
	DESCRIBE_FLAG(UMOUNT_NOFOLLOW),
};

static const char *swap_flags[64] = {
	DESCRIBE_FLAG(SWAP_FLAG_DISCARD),
};

static const char *splice_flags[64] = {
	DESCRIBE_FLAG(SPLICE_F_MOVE),
	DESCRIBE_FLAG(SPLICE_F_NONBLOCK),
	DESCRIBE_FLAG(SPLICE_F_MORE),
	DESCRIBE_FLAG(SPLICE_F_GIFT),
};

static const char *sync_file_range_flags[64] = {
	DESCRIBE_FLAG(SYNC_FILE_RANGE_WAIT_BEFORE),
	DESCRIBE_FLAG(SYNC_FILE_RANGE_WRITE),
	DESCRIBE_FLAG(SYNC_FILE_RANGE_WAIT_AFTER),
};

static const char *timerfd_settime_flags[64] = {
	DESCRIBE_FLAG(TFD_TIMER_ABSTIME),
	DESCRIBE_FLAG(TFD_TIMER_CANCEL_ON_SET),
};

static const char *perf_event_open_flags[64] = {
	DESCRIBE_FLAG(PERF_FLAG_FD_CLOEXEC),
	DESCRIBE_FLAG(PERF_FLAG_FD_NO_GROUP),
	DESCRIBE_FLAG(PERF_FLAG_FD_OUTPUT),
	DESCRIBE_FLAG(PERF_FLAG_PID_CGROUP),
};

static const char *module_init_flags[64] = {
	DESCRIBE_FLAG(MODULE_INIT_IGNORE_MODVERSIONS),
	DESCRIBE_FLAG(MODULE_INIT_IGNORE_VERMAGIC),
};

#ifndef GRND_INSECURE
#define GRND_INSECURE 0x4
#endif

static const char *getrandom_flags[64] = {
	DESCRIBE_FLAG(GRND_RANDOM),
	DESCRIBE_FLAG(GRND_NONBLOCK),
	DESCRIBE_FLAG(GRND_INSECURE),
};

#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif
#ifndef STATX_DIOALIGN
#define STATX_DIOALIGN 0x00002000U
#endif

static const char *statx_mask[64] = {
	DESCRIBE_FLAG(STATX_TYPE),
	DESCRIBE_FLAG(STATX_MODE),
	DESCRIBE_FLAG(STATX_NLINK),
	DESCRIBE_FLAG(STATX_UID),
	DESCRIBE_FLAG(STATX_GID),
	DESCRIBE_FLAG(STATX_ATIME),
	DESCRIBE_FLAG(STATX_MTIME),
	DESCRIBE_FLAG(STATX_CTIME),
	DESCRIBE_FLAG(STATX_INO),
	DESCRIBE_FLAG(STATX_SIZE),
	DESCRIBE_FLAG(STATX_BLOCKS),
	DESCRIBE_FLAG(STATX_BTIME),
	DESCRIBE_FLAG(STATX_MNT_ID),
	DESCRIBE_FLAG(STATX_DIOALIGN),
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

enum {
	DESCRIBE_PRINT_ZERO_ENUMS = 0x1,
	DESCRIBE_AS_FILE_MODE = 0x2,
};

typedef uint8_t description_format_options;

static inline size_t format_octal(uintptr_t value, char buffer[])
{
	buffer[0] = '0';
	if (value == 0) {
		buffer[1] = '\0';
		return 1;
	}
	size_t i = 1;
	while (value != 0) {
		buffer[i++] = "0123456789abcdef"[(unsigned char)value & 0x7];
		value = value >> 3;
	}
	buffer[i] = '\0';
	fs_reverse(&buffer[1], i-1);
	return i+1;
}

static char *copy_enum_flags_value_description(const struct loader_context *context, uintptr_t value, const struct enum_option *options, size_t sizeof_options, const char *flags[64], description_format_options description_options)
{
	char num_buf[64];
	if (flags == NULL) {
		for (size_t i = 0; i < sizeof_options / sizeof(*options); i++) {
			if (value == options[i].value) {
				return strdup(options[i].description);
			}
		}
		if (description_options & DESCRIBE_AS_FILE_MODE) {
			format_octal(value, num_buf);
			return strdup(num_buf);
		}
		return copy_address_details(context, (const void *)value, false);
	}
	// calculate length
	size_t length = 0;
	uintptr_t remaining = 0;
	for_each_bit(value, bit, i) {
		if (flags[i] != NULL) {
			length += fs_strlen(flags[i]) + 1;
		} else {
			remaining |= bit;
		}
	}
	const char *suffix = NULL;
	size_t suffix_len = 0;
	if (length == 0 || remaining != 0 || (description_options & DESCRIBE_PRINT_ZERO_ENUMS)) {
		for (size_t i = 0; i < sizeof_options / sizeof(*options); i++) {
			if (remaining == options[i].value) {
				suffix = options[i].description;
				suffix_len = fs_strlen(suffix);
				length += suffix_len + 1;
				break;
			}
		}
		if (suffix == NULL && (length == 0 || remaining != 0)) {
			suffix = num_buf;
			suffix_len = (description_options & DESCRIBE_AS_FILE_MODE) ? format_octal(remaining, num_buf) : (remaining < PAGE_SIZE ? fs_utoa(remaining, num_buf) : fs_utoah(remaining, num_buf));
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
	for_each_bit(value, bit, i) {
		if (flags[i] != NULL) {
			next = fs_strcpy(next, flags[i]);
			*next++ = '|';
		}
	}
	next--;
	*next = '\0';
	return result;
}

static char *copy_enum_flags_description(const struct loader_context *context, struct register_state state, const struct enum_option *options, size_t sizeof_options, const char *flags[64], description_format_options description_options)
{
	if (register_is_exactly_known(&state)) {
		return copy_enum_flags_value_description(context, state.value, options, sizeof_options, flags, description_options);
	}
	if (state.value == 0) {
		if (state.max == ~(uintptr_t)0) {
			return strdup("any");
		}
		if (state.max == 0xffffffff) {
			return strdup("any u32");
		}
		if (state.max == 0xffff) {
			return strdup("any u16");
		}
		if (state.max == 0xff) {
			return strdup("any u8");
		}
	}
	char *low = copy_enum_flags_value_description(context, state.value, options, sizeof_options, flags, description_options);
	size_t low_size = strlen(low);
	char *high = copy_enum_flags_value_description(context, state.max, options, sizeof_options, flags, description_options);
	size_t high_size = strlen(high);
	char *buf = realloc(low, low_size + 1 + high_size + 1);
	// memcpy(buf, low, low_size);
	buf[low_size] = '-';
	memcpy(&buf[low_size + 1], high, high_size + 1);
	free(high);
	return buf;
}

static char *copy_argument_description(const struct loader_context *context, struct register_state state, uint8_t argument_type)
{
	switch (argument_type) {
		case SYSCALL_ARG_IS_FD:
			return copy_enum_flags_description(context, state, file_descriptors, sizeof(file_descriptors), NULL, false);
		case SYSCALL_ARG_IS_PROT:
			return copy_enum_flags_description(context, state, prots, sizeof(prots), prot_flags, false);
		case SYSCALL_ARG_IS_MAP_FLAGS:
			return copy_enum_flags_description(context, state, maps, sizeof(maps), map_flags, DESCRIBE_PRINT_ZERO_ENUMS);
		case SYSCALL_ARG_IS_REMAP_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, remap_flags, false);
		case SYSCALL_ARG_IS_OPEN_FLAGS:
			return copy_enum_flags_description(context, state, opens, sizeof(opens), open_flags, DESCRIBE_PRINT_ZERO_ENUMS);
		case SYSCALL_ARG_IS_SIGNUM:
			return copy_enum_flags_description(context, state, signums, sizeof(signums), NULL, false);
		case SYSCALL_ARG_IS_IOCTL:
			return copy_enum_flags_description(context, state, ioctls, sizeof(ioctls), NULL, false);
		case SYSCALL_ARG_IS_SIGHOW:
			return copy_enum_flags_description(context, state, sighows, sizeof(sighows), NULL, false);
		case SYSCALL_ARG_IS_MADVISE:
			return copy_enum_flags_description(context, state, madvises, sizeof(madvises), NULL, false);
		case SYSCALL_ARG_IS_FCNTL:
			return copy_enum_flags_description(context, state, fcntls, sizeof(fcntls), NULL, false);
		case SYSCALL_ARG_IS_RLIMIT:
			return copy_enum_flags_description(context, state, rlimits, sizeof(rlimits), NULL, false);
		case SYSCALL_ARG_IS_SOCKET_DOMAIN:
			return copy_enum_flags_description(context, state, socket_domains, sizeof(socket_domains), NULL, false);
		case SYSCALL_ARG_IS_SOCKET_TYPE:
			return copy_enum_flags_description(context, state, socket_types, sizeof(socket_types), socket_flags, DESCRIBE_PRINT_ZERO_ENUMS);
		case SYSCALL_ARG_IS_CLOCK_ID:
			return copy_enum_flags_description(context, state, clock_ids, sizeof(clock_ids), NULL, false);
		case SYSCALL_ARG_IS_SOCKET_LEVEL:
			return copy_enum_flags_description(context, state, socket_levels, sizeof(socket_levels), NULL, false);
		case SYSCALL_ARG_IS_SOCKET_OPTION:
			return copy_enum_flags_description(context, state, socket_options, sizeof(socket_options), NULL, false);
		case SYSCALL_ARG_IS_ACCESS_MODE:
			return copy_enum_flags_description(context, state, access_modes, sizeof(access_modes), access_mode_flags, false);
		case SYSCALL_ARG_IS_ACCESSAT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, accessat_flags, false);
		case SYSCALL_ARG_IS_REMOVEAT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, removeat_flags, false);
		case SYSCALL_ARG_IS_MSYNC_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, msync_flags, false);
		case SYSCALL_ARG_IS_OFLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, open_flags, false);
		case SYSCALL_ARG_IS_MSG_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, msg_flags, false);
		case SYSCALL_ARG_IS_SHUTDOWN_HOW:
			return copy_enum_flags_description(context, state, shutdown_hows, sizeof(shutdown_hows), NULL, false);
		case SYSCALL_ARG_IS_FUTEX_OP:
			return copy_enum_flags_description(context, state, futex_operations, sizeof(futex_operations), futex_flags, DESCRIBE_PRINT_ZERO_ENUMS);
		case SYSCALL_ARG_IS_SIGNALFD_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, signalfd_flags, false);
		case SYSCALL_ARG_IS_TIMERFD_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, timerfd_flags, false);
		case SYSCALL_ARG_IS_SOCKET_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, socket_flags, false);
		case SYSCALL_ARG_IS_PRCTL:
			return copy_enum_flags_description(context, state, prctls, sizeof(prctls), NULL, false);
		case SYSCALL_ARG_IS_CLONEFLAGS:
			return copy_enum_flags_description(context, state, signums, sizeof(signums), clone_flags, DESCRIBE_PRINT_ZERO_ENUMS);
		case SYSCALL_ARG_IS_UNSHARE_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, unshare_flags, false);
		case SYSCALL_ARG_IS_SHM_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, shm_flags, DESCRIBE_AS_FILE_MODE);
		case SYSCALL_ARG_IS_EVENTFD_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, eventfd_flags, false);
		case SYSCALL_ARG_IS_EPOLL_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, epoll_flags, false);
		case SYSCALL_ARG_IS_XATTR_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, xattr_flags, false);
		case SYSCALL_ARG_IS_TIMER_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, timer_flags, false);
		case SYSCALL_ARG_IS_WAIT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, wait_flags, false);
		case SYSCALL_ARG_IS_WAITIDTYPE:
			return copy_enum_flags_description(context, state, wait_idtypes, sizeof(wait_idtypes), NULL, false);
		case SYSCALL_ARG_IS_INOTIFY_EVENT_MASK:
			return copy_enum_flags_description(context, state, NULL, 0, inotify_event_flags, false);
		case SYSCALL_ARG_IS_INOTIFY_INIT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, inotify_init_flags, false);
		case SYSCALL_ARG_IS_SECCOMP_OPERATION:
			return copy_enum_flags_description(context, state, seccomp_operations, sizeof(seccomp_operations), NULL, false);
		case SYSCALL_ARG_IS_MEMFD_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, memfd_flags, false);
		case SYSCALL_ARG_IS_BPF_COMMAND:
			return copy_enum_flags_description(context, state, bpf_commands, sizeof(bpf_commands), NULL, false);
		case SYSCALL_ARG_IS_USERFAULTFD_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, userfaultfd_flags, false);
		case SYSCALL_ARG_IS_MLOCKALL_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, mlockall_flags, false);
		case SYSCALL_ARG_IS_UMOUNT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, umount_flags, false);
		case SYSCALL_ARG_IS_SWAP_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, swap_flags, false);
		case SYSCALL_ARG_IS_SPLICE_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, splice_flags, false);
		case SYSCALL_ARG_IS_SYNC_FILE_RANGE_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, sync_file_range_flags, false);
		case SYSCALL_ARG_IS_TIMERFD_SETTIME_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, timerfd_settime_flags, false);
		case SYSCALL_ARG_IS_PERF_EVENT_OPEN_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, perf_event_open_flags, false);
		case SYSCALL_ARG_IS_MODULE_INIT_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, module_init_flags, false);
		case SYSCALL_ARG_IS_GETRANDOM_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, getrandom_flags, false);
		case SYSCALL_ARG_IS_MEMBARRIER_COMMAND:
			return copy_enum_flags_description(context, state, membarrier_commands, sizeof(membarrier_commands), NULL, false);
		case SYSCALL_ARG_IS_STATX_MASK:
			return copy_enum_flags_description(context, state, NULL, 0, statx_mask, false);
		case SYSCALL_ARG_IS_FLOCK_OPERATION:
			return copy_enum_flags_description(context, state, flock_operations, sizeof(flock_operations), flock_flags, false);
		case SYSCALL_ARG_IS_ITIMER_WHICH:
			return copy_enum_flags_description(context, state, itimer_whiches, sizeof(itimer_whiches), NULL, false);
		case SYSCALL_ARG_IS_SEEK_WHENCE:
			return copy_enum_flags_description(context, state, seek_whences, sizeof(seek_whences), NULL, false);
		case SYSCALL_ARG_IS_SHMCTL_COMMAND:
			return copy_enum_flags_description(context, state, shmctl_commands, sizeof(shmctl_commands), NULL, false);
		case SYSCALL_ARG_IS_SEMCTL_COMMAND:
			return copy_enum_flags_description(context, state, semctl_commands, sizeof(semctl_commands), NULL, false);
		case SYSCALL_ARG_IS_PTRACE_REQUEST:
			return copy_enum_flags_description(context, state, ptrace_requests, sizeof(ptrace_requests), NULL, false);
		case SYSCALL_ARG_IS_SEM_FLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, sem_flags, DESCRIBE_AS_FILE_MODE);
		case SYSCALL_ARG_IS_PID:
			if (context->pid != 0 && register_is_exactly_known(&state) && state.value == (uintptr_t)context->pid) {
				return strdup("getpid()");
			} else {
				return copy_register_state_description(context, state);
			}
		case SYSCALL_ARG_IS_MODE:
		case SYSCALL_ARG_IS_MODEFLAGS:
			return copy_enum_flags_description(context, state, NULL, 0, NULL, DESCRIBE_AS_FILE_MODE);
		case SYSCALL_ARG_IS_SOCKET_PROTOCOL:
		default:
			return copy_register_state_description(context, state);
	}
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
			args[i] = copy_argument_description(context, registers.registers[reg], info.arguments[i] & SYSCALL_ARG_TYPE_MASK);
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
