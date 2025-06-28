#ifndef LINUX_H
#define LINUX_H

#ifdef __linux__
#include <linux/binfmts.h>
#else
#define BINPRM_BUF_SIZE 256
#endif
#include <stdint.h>

// define LINUX_SYS_* for syscall names
#define CONCAT(a, b) CONCAT_INNER(a, b)
#define CONCAT_INNER(a, b) a##b

enum
{
#define SYSCALL_DEF(name, ...) LINUX_SYS_##name,
#define SYSCALL_DEF_EMPTY CONCAT(LINUX_SYS_UNUSED_, __LINE__),
#include "syscall_defs.h"
#undef SYSCALL_DEF
#undef SYSCALL_DEF_EMPTY
};

#define LINUX_AT_FDCWD -100

#define LINUX_AT_SYMLINK_NOFOLLOW 0x100   /* Do not follow symbolic links.  */
#define LINUX_AT_EACCESS               \
	0x200 /* Test access permitted for \
	         effective IDs, not real IDs.  */
#define LINUX_AT_REMOVEDIR               \
	0x200   /* Remove directory instead of \
	     unlinking file.  */
#define LINUX_AT_SYMLINK_FOLLOW 0x400   /* Follow symbolic links.  */
#define LINUX_AT_NO_AUTOMOUNT 0x800 /* Suppress terminal automount traversal */
#define LINUX_AT_EMPTY_PATH 0x1000 /* Allow empty relative pathname */

#define LINUX_AT_STATX_SYNC_TYPE 0x6000 /* Type of synchronisation required from statx() */
#define LINUX_AT_STATX_SYNC_AS_STAT 0x0000 /* - Do whatever stat() does */
#define LINUX_AT_STATX_FORCE_SYNC 0x2000 /* - Force the attributes to be sync'd with the server */
#define LINUX_AT_STATX_DONT_SYNC 0x4000 /* - Don't sync attributes with the server */

#define LINUX_AT_RECURSIVE 0x8000 /* Apply to the entire subtree */

/* Flags for name_to_handle_at(2). We reuse AT_ flag space to save bits... */
#define LINUX_AT_HANDLE_FID                        \
	LINUX_AT_REMOVEDIR /* file handle is needed to \
compare object identity and may not                \
be usable to open_by_handle_at(2) */

#define LINUX_PROT_READ 0x1  /* page can be read */
#define LINUX_PROT_WRITE 0x2  /* page can be written */
#define LINUX_PROT_EXEC 0x4  /* page can be executed */
#define LINUX_PROT_SEM 0x8  /* page may be used for atomic ops */
#define LINUX_PROT_NONE 0x0  /* page can not be accessed */

#define LINUX_MAP_SHARED 0x01  /* Share changes */
#define LINUX_MAP_PRIVATE 0x02  /* Changes are private */
#define LINUX_MAP_TYPE 0x0f  /* Mask for type of mapping */
#define LINUX_MAP_FIXED 0x10  /* Interpret addr exactly */
#define LINUX_MAP_ANONYMOUS 0x20  /* don't use a file */

/* 0x0100 - 0x4000 flags are defined in asm-generic/mman.h */
#define LINUX_MAP_POPULATE 0x008000 /* populate (prefault) pagetables */
#define LINUX_MAP_NONBLOCK 0x010000 /* do not block on IO */
#define LINUX_MAP_STACK 0x020000 /* give out an address that is best suited for process/thread stacks */
#define LINUX_MAP_HUGETLB 0x040000 /* create a huge page mapping */
#define LINUX_MAP_SYNC 0x080000 /* perform synchronous page faults for the mapping */
#define LINUX_MAP_FIXED_NOREPLACE 0x100000 /* MAP_FIXED which doesn't unmap underlying mapping */

#define LINUX_MAP_UNINITIALIZED                      \
	0x4000000 /* For anonymous mmap, memory could be \
	           * uninitialized */

#define LINUX_O_ACCMODE 00000003
#define LINUX_O_RDONLY 00000000
#define LINUX_O_WRONLY 00000001
#define LINUX_O_RDWR 00000002
#ifndef LINUX_O_CREAT
#define LINUX_O_CREAT 00000100 /* not fcntl */
#endif
#ifndef LINUX_O_EXCL
#define LINUX_O_EXCL 00000200 /* not fcntl */
#endif
#ifndef LINUX_O_NOCTTY
#define LINUX_O_NOCTTY 00000400 /* not fcntl */
#endif
#ifndef LINUX_O_TRUNC
#define LINUX_O_TRUNC 00001000 /* not fcntl */
#endif
#ifndef LINUX_O_APPEND
#define LINUX_O_APPEND 00002000
#endif
#ifndef LINUX_O_NONBLOCK
#define LINUX_O_NONBLOCK 00004000
#endif
#ifndef LINUX_O_DSYNC
#define LINUX_O_DSYNC 00010000 /* used to be O_SYNC, see below */
#endif
#ifndef LINUX_FASYNC
#define LINUX_FASYNC 00020000 /* fcntl, for BSD compatibility */
#endif
#ifndef LINUX_O_DIRECT
#define LINUX_O_DIRECT 00040000 /* direct disk access hint */
#endif
#ifndef LINUX_O_LARGEFILE
#define LINUX_O_LARGEFILE 00100000
#endif
#ifndef LINUX_O_DIRECTORY
#define LINUX_O_DIRECTORY 00200000 /* must be a directory */
#endif
#ifndef LINUX_O_NOFOLLOW
#define LINUX_O_NOFOLLOW 00400000 /* don't follow links */
#endif
#ifndef LINUX_O_NOATIME
#define LINUX_O_NOATIME 01000000
#endif
#ifndef LINUX_O_CLOEXEC
#define LINUX_O_CLOEXEC 02000000 /* set close_on_exec */
#endif

/*
 * Before Linux 2.6.33 only O_DSYNC semantics were implemented, but using
 * the O_SYNC flag.  We continue to use the existing numerical value
 * for O_DSYNC semantics now, but using the correct symbolic name for it.
 * This new value is used to request true Posix O_SYNC semantics.  It is
 * defined in this strange way to make sure applications compiled against
 * new headers get at least O_DSYNC semantics on older kernels.
 *
 * This has the nice side-effect that we can simply test for O_DSYNC
 * wherever we do not care if O_DSYNC or O_SYNC is used.
 *
 * Note: __O_SYNC must never be used directly.
 */
#ifndef LINUX_O_SYNC
#define LINUX___O_SYNC 04000000
#define LINUX_O_SYNC (LINUX___O_SYNC | LINUX_O_DSYNC)
#endif

#ifndef LINUX_O_PATH
#define LINUX_O_PATH 010000000
#endif

#ifndef LINUX___O_TMPFILE
#define LINUX___O_TMPFILE 020000000
#endif

/* a horrid kludge trying to make sure that this will fail on old kernels */
#define LINUX_O_TMPFILE (LINUX___O_TMPFILE | LINUX_O_DIRECTORY)

#ifndef LINUX_O_NDELAY
#define LINUX_O_NDELAY LINUX_O_NONBLOCK
#endif

struct linux_statx_timestamp
{
	int64_t tv_sec;
	uint32_t tv_nsec;
	int32_t __reserved;
};

struct linux_statx
{
	/* 0x00 */
	uint32_t stx_mask; /* What results were written [uncond] */
	uint32_t stx_blksize; /* Preferred general I/O size [uncond] */
	uint64_t stx_attributes; /* Flags conveying information about the file [uncond] */
	/* 0x10 */
	uint32_t stx_nlink; /* Number of hard links */
	uint32_t stx_uid; /* User ID of owner */
	uint32_t stx_gid; /* Group ID of owner */
	uint16_t stx_mode; /* File mode */
	uint16_t __spare0[1];
	/* 0x20 */
	uint64_t stx_ino; /* Inode number */
	uint64_t stx_size; /* File size */
	uint64_t stx_blocks; /* Number of 512-byte blocks allocated */
	uint64_t stx_attributes_mask; /* Mask to show what's supported in stx_attributes */
	/* 0x40 */
	struct linux_statx_timestamp stx_atime; /* Last access time */
	struct linux_statx_timestamp stx_btime; /* File creation time */
	struct linux_statx_timestamp stx_ctime; /* Last attribute change time */
	struct linux_statx_timestamp stx_mtime; /* Last data modification time */
	/* 0x80 */
	uint32_t stx_rdev_major; /* Device ID of special file [if bdev/cdev] */
	uint32_t stx_rdev_minor;
	uint32_t stx_dev_major; /* ID of device containing file [uncond] */
	uint32_t stx_dev_minor;
	/* 0x90 */
	uint64_t stx_mnt_id;
	uint32_t stx_dio_mem_align; /* Memory buffer alignment for direct I/O */
	uint32_t stx_dio_offset_align; /* File offset alignment for direct I/O */
	/* 0xa0 */
	uint64_t __spare3[12]; /* Spare space for future expansion */
	/* 0x100 */
};

typedef unsigned int linux_tcflag_t;
typedef unsigned char linux_cc_t;

struct linux_termios
{
	linux_tcflag_t c_iflag;
	linux_tcflag_t c_oflag;
	linux_tcflag_t c_cflag;
	linux_tcflag_t c_lflag;
	linux_cc_t c_line;
	linux_cc_t c_cc[19];
};

#define __NEW_UTS_LEN 64

struct linux_new_utsname
{
	char linux_sysname[__NEW_UTS_LEN + 1];
	char linux_nodename[__NEW_UTS_LEN + 1];
	char linux_release[__NEW_UTS_LEN + 1];
	char linux_version[__NEW_UTS_LEN + 1];
	char linux_machine[__NEW_UTS_LEN + 1];
	char linux_domainname[__NEW_UTS_LEN + 1];
};

#ifdef __aarch64__
struct linux_stat
{
	dev_t st_dev;
	ino_t st_ino;
	mode_t st_mode;
	nlink_t st_nlink;
	uid_t st_uid;
	gid_t st_gid;
	dev_t st_rdev;
	unsigned long __pad;
	off_t st_size;
	blksize_t st_blksize;
	int __pad2;
	blkcnt_t st_blocks;
	long st_atime_sec;
	long st_atime_nsec;
	long st_mtime_sec;
	long st_mtime_nsec;
	long st_ctime_sec;
	long st_ctime_nsec;
	unsigned __unused_padding[2];
};
#endif

enum
{
	LINUX_EPERM = 1,
	LINUX_ENOENT = 2,
	LINUX_ESRCH = 3,
	LINUX_EINTR = 4,
	LINUX_EIO = 5,
	LINUX_ENXIO = 6,
	LINUX_E2BIG = 7,
	LINUX_ENOEXEC = 8,
	LINUX_EBADF = 9,
	LINUX_ECHILD = 10,
	LINUX_EAGAIN = 11,
	LINUX_ENOMEM = 12,
	LINUX_EACCES = 13,
	LINUX_EFAULT = 14,
	LINUX_ENOTBLK = 15,
	LINUX_EBUSY = 16,
	LINUX_EEXIST = 17,
	LINUX_EXDEV = 18,
	LINUX_ENODEV = 19,
	LINUX_ENOTDIR = 20,
	LINUX_EISDIR = 21,
	LINUX_EINVAL = 22,
	LINUX_ENFILE = 23,
	LINUX_EMFILE = 24,
	LINUX_ENOTTY = 25,
	LINUX_ETXTBSY = 26,
	LINUX_EFBIG = 27,
	LINUX_ENOSPC = 28,
	LINUX_ESPIPE = 29,
	LINUX_EROFS = 30,
	LINUX_EMLINK = 31,
	LINUX_EPIPE = 32,
	LINUX_EDOM = 33,
	LINUX_ERANGE = 34,
	LINUX_EDEADLK = 35,
	LINUX_ENAMETOOLONG = 36,
	LINUX_ENOLCK = 37,
	LINUX_ENOSYS = 38,
	LINUX_ENOTEMPTY = 39,
	LINUX_ELOOP = 40,
	LINUX_EWOULDBLOCK = 11,
	LINUX_ENOMSG = 42,
	LINUX_EIDRM = 43,
	LINUX_ECHRNG = 44,
	LINUX_EL2NSYNC = 45,
	LINUX_EL3HLT = 46,
	LINUX_EL3RST = 47,
	LINUX_ELNRNG = 48,
	LINUX_EUNATCH = 49,
	LINUX_ENOCSI = 50,
	LINUX_EL2HLT = 51,
	LINUX_EBADE = 52,
	LINUX_EBADR = 53,
	LINUX_EXFULL = 54,
	LINUX_ENOANO = 55,
	LINUX_EBADRQC = 56,
	LINUX_EBADSLT = 57,
	LINUX_EDEADLOCK = 35,
	LINUX_EBFONT = 59,
	LINUX_ENOSTR = 60,
	LINUX_ENODATA = 61,
	LINUX_ETIME = 62,
	LINUX_ENOSR = 63,
	LINUX_ENONET = 64,
	LINUX_ENOPKG = 65,
	LINUX_EREMOTE = 66,
	LINUX_ENOLINK = 67,
	LINUX_EADV = 68,
	LINUX_ESRMNT = 69,
	LINUX_ECOMM = 70,
	LINUX_EPROTO = 71,
	LINUX_EMULTIHOP = 72,
	LINUX_EDOTDOT = 73,
	LINUX_EBADMSG = 74,
	LINUX_EOVERFLOW = 75,
	LINUX_ENOTUNIQ = 76,
	LINUX_EBADFD = 77,
	LINUX_EREMCHG = 78,
	LINUX_ELIBACC = 79,
	LINUX_ELIBBAD = 80,
	LINUX_ELIBSCN = 81,
	LINUX_ELIBMAX = 82,
	LINUX_ELIBEXEC = 83,
	LINUX_EILSEQ = 84,
	LINUX_ERESTART = 85,
	LINUX_ESTRPIPE = 86,
	LINUX_EUSERS = 87,
	LINUX_ENOTSOCK = 88,
	LINUX_EDESTADDRREQ = 89,
	LINUX_EMSGSIZE = 90,
	LINUX_EPROTOTYPE = 91,
	LINUX_ENOPROTOOPT = 92,
	LINUX_EPROTONOSUPPORT = 93,
	LINUX_ESOCKTNOSUPPORT = 94,
	LINUX_EOPNOTSUPP = 95,
	LINUX_EPFNOSUPPORT = 96,
	LINUX_EAFNOSUPPORT = 97,
	LINUX_EADDRINUSE = 98,
	LINUX_EADDRNOTAVAIL = 99,
	LINUX_ENETDOWN = 100,
	LINUX_ENETUNREACH = 101,
	LINUX_ENETRESET = 102,
	LINUX_ECONNABORTED = 103,
	LINUX_ECONNRESET = 104,
	LINUX_ENOBUFS = 105,
	LINUX_EISCONN = 106,
	LINUX_ENOTCONN = 107,
	LINUX_ESHUTDOWN = 108,
	LINUX_ETOOMANYREFS = 109,
	LINUX_ETIMEDOUT = 110,
	LINUX_ECONNREFUSED = 111,
	LINUX_EHOSTDOWN = 112,
	LINUX_EHOSTUNREACH = 113,
	LINUX_EALREADY = 114,
	LINUX_EINPROGRESS = 115,
	LINUX_ESTALE = 116,
	LINUX_EUCLEAN = 117,
	LINUX_ENOTNAM = 118,
	LINUX_ENAVAIL = 119,
	LINUX_EISNAM = 120,
	LINUX_EREMOTEIO = 121,
	LINUX_EDQUOT = 122,
	LINUX_ENOMEDIUM = 123,
	LINUX_EMEDIUMTYPE = 124,
	LINUX_ECANCELED = 125,
	LINUX_ENOKEY = 126,
	LINUX_EKEYEXPIRED = 127,
	LINUX_EKEYREVOKED = 128,
	LINUX_EKEYREJECTED = 129,
	LINUX_EOWNERDEAD = 130,
	LINUX_ENOTRECOVERABLE = 131,
	LINUX_ERFKILL = 132,
	LINUX_EHWPOISON = 133,
	LINUX_ENOTSUP = 95,
};

static inline intptr_t translate_errno_to_linux(int err)
{
	switch (err) {
#ifdef EPERM
		case EPERM:
			return LINUX_EPERM;
#endif
#ifdef ENOENT
		case ENOENT:
			return LINUX_ENOENT;
#endif
#ifdef ESRCH
		case ESRCH:
			return LINUX_ESRCH;
#endif
#ifdef EINTR
		case EINTR:
			return LINUX_EINTR;
#endif
#ifdef EIO
		case EIO:
			return LINUX_EIO;
#endif
#ifdef ENXIO
		case ENXIO:
			return LINUX_ENXIO;
#endif
#ifdef E2BIG
		case E2BIG:
			return LINUX_E2BIG;
#endif
#ifdef ENOEXEC
		case ENOEXEC:
			return LINUX_ENOEXEC;
#endif
#ifdef EBADF
		case EBADF:
			return LINUX_EBADF;
#endif
#ifdef ECHILD
		case ECHILD:
			return LINUX_ECHILD;
#endif
#ifdef EAGAIN
		case EAGAIN:
			return LINUX_EAGAIN;
#endif
#ifdef ENOMEM
		case ENOMEM:
			return LINUX_ENOMEM;
#endif
#ifdef EACCES
		case EACCES:
			return LINUX_EACCES;
#endif
#ifdef EFAULT
		case EFAULT:
			return LINUX_EFAULT;
#endif
#ifdef ENOTBLK
		case ENOTBLK:
			return LINUX_ENOTBLK;
#endif
#ifdef EBUSY
		case EBUSY:
			return LINUX_EBUSY;
#endif
#ifdef EEXIST
		case EEXIST:
			return LINUX_EEXIST;
#endif
#ifdef EXDEV
		case EXDEV:
			return LINUX_EXDEV;
#endif
#ifdef ENODEV
		case ENODEV:
			return LINUX_ENODEV;
#endif
#ifdef ENOTDIR
		case ENOTDIR:
			return LINUX_ENOTDIR;
#endif
#ifdef EISDIR
		case EISDIR:
			return LINUX_EISDIR;
#endif
#ifdef EINVAL
		case EINVAL:
			return LINUX_EINVAL;
#endif
#ifdef ENFILE
		case ENFILE:
			return LINUX_ENFILE;
#endif
#ifdef EMFILE
		case EMFILE:
			return LINUX_EMFILE;
#endif
#ifdef ENOTTY
		case ENOTTY:
			return LINUX_ENOTTY;
#endif
#ifdef ETXTBSY
		case ETXTBSY:
			return LINUX_ETXTBSY;
#endif
#ifdef EFBIG
		case EFBIG:
			return LINUX_EFBIG;
#endif
#ifdef ENOSPC
		case ENOSPC:
			return LINUX_ENOSPC;
#endif
#ifdef ESPIPE
		case ESPIPE:
			return LINUX_ESPIPE;
#endif
#ifdef EROFS
		case EROFS:
			return LINUX_EROFS;
#endif
#ifdef EMLINK
		case EMLINK:
			return LINUX_EMLINK;
#endif
#ifdef EPIPE
		case EPIPE:
			return LINUX_EPIPE;
#endif
#ifdef EDOM
		case EDOM:
			return LINUX_EDOM;
#endif
#ifdef ERANGE
		case ERANGE:
			return LINUX_ERANGE;
#endif
#ifdef EDEADLK
		case EDEADLK:
			return LINUX_EDEADLK;
#endif
#ifdef ENAMETOOLONG
		case ENAMETOOLONG:
			return LINUX_ENAMETOOLONG;
#endif
#ifdef ENOLCK
		case ENOLCK:
			return LINUX_ENOLCK;
#endif
#ifdef ENOSYS
		case ENOSYS:
			return LINUX_ENOSYS;
#endif
#ifdef ENOTEMPTY
		case ENOTEMPTY:
			return LINUX_ENOTEMPTY;
#endif
#ifdef ELOOP
		case ELOOP:
			return LINUX_ELOOP;
#endif
// #ifdef EWOULDBLOCK
// 	case EWOULDBLOCK:
// 		return LINUX_EWOULDBLOCK;
// #endif
#ifdef ENOMSG
		case ENOMSG:
			return LINUX_ENOMSG;
#endif
#ifdef EIDRM
		case EIDRM:
			return LINUX_EIDRM;
#endif
#ifdef ECHRNG
		case ECHRNG:
			return LINUX_ECHRNG;
#endif
#ifdef EL2NSYNC
		case EL2NSYNC:
			return LINUX_EL2NSYNC;
#endif
#ifdef EL3HLT
		case EL3HLT:
			return LINUX_EL3HLT;
#endif
#ifdef EL3RST
		case EL3RST:
			return LINUX_EL3RST;
#endif
#ifdef ELNRNG
		case ELNRNG:
			return LINUX_ELNRNG;
#endif
#ifdef EUNATCH
		case EUNATCH:
			return LINUX_EUNATCH;
#endif
#ifdef ENOCSI
		case ENOCSI:
			return LINUX_ENOCSI;
#endif
#ifdef EL2HLT
		case EL2HLT:
			return LINUX_EL2HLT;
#endif
#ifdef EBADE
		case EBADE:
			return LINUX_EBADE;
#endif
#ifdef EBADR
		case EBADR:
			return LINUX_EBADR;
#endif
#ifdef EXFULL
		case EXFULL:
			return LINUX_EXFULL;
#endif
#ifdef ENOANO
		case ENOANO:
			return LINUX_ENOANO;
#endif
#ifdef EBADRQC
		case EBADRQC:
			return LINUX_EBADRQC;
#endif
#ifdef EBADSLT
		case EBADSLT:
			return LINUX_EBADSLT;
#endif
#ifndef __linux__
#ifdef EDEADLOCK
		case EDEADLOCK:
			return LINUX_EDEADLOCK;
#endif
#endif
#ifdef EBFONT
		case EBFONT:
			return LINUX_EBFONT;
#endif
#ifdef ENOSTR
		case ENOSTR:
			return LINUX_ENOSTR;
#endif
#ifdef ENODATA
		case ENODATA:
			return LINUX_ENODATA;
#endif
#ifdef ETIME
		case ETIME:
			return LINUX_ETIME;
#endif
#ifdef ENOSR
		case ENOSR:
			return LINUX_ENOSR;
#endif
#ifdef ENONET
		case ENONET:
			return LINUX_ENONET;
#endif
#ifdef ENOPKG
		case ENOPKG:
			return LINUX_ENOPKG;
#endif
#ifdef EREMOTE
		case EREMOTE:
			return LINUX_EREMOTE;
#endif
#ifdef ENOLINK
		case ENOLINK:
			return LINUX_ENOLINK;
#endif
#ifdef EADV
		case EADV:
			return LINUX_EADV;
#endif
#ifdef ESRMNT
		case ESRMNT:
			return LINUX_ESRMNT;
#endif
#ifdef ECOMM
		case ECOMM:
			return LINUX_ECOMM;
#endif
#ifdef EPROTO
		case EPROTO:
			return LINUX_EPROTO;
#endif
#ifdef EMULTIHOP
		case EMULTIHOP:
			return LINUX_EMULTIHOP;
#endif
#ifdef EDOTDOT
		case EDOTDOT:
			return LINUX_EDOTDOT;
#endif
#ifdef EBADMSG
		case EBADMSG:
			return LINUX_EBADMSG;
#endif
#ifdef EOVERFLOW
		case EOVERFLOW:
			return LINUX_EOVERFLOW;
#endif
#ifdef ENOTUNIQ
		case ENOTUNIQ:
			return LINUX_ENOTUNIQ;
#endif
#ifdef EBADFD
		case EBADFD:
			return LINUX_EBADFD;
#endif
#ifdef EREMCHG
		case EREMCHG:
			return LINUX_EREMCHG;
#endif
#ifdef ELIBACC
		case ELIBACC:
			return LINUX_ELIBACC;
#endif
#ifdef ELIBBAD
		case ELIBBAD:
			return LINUX_ELIBBAD;
#endif
#ifdef ELIBSCN
		case ELIBSCN:
			return LINUX_ELIBSCN;
#endif
#ifdef ELIBMAX
		case ELIBMAX:
			return LINUX_ELIBMAX;
#endif
#ifdef ELIBEXEC
		case ELIBEXEC:
			return LINUX_ELIBEXEC;
#endif
#ifdef EILSEQ
		case EILSEQ:
			return LINUX_EILSEQ;
#endif
#ifdef ERESTART
		case ERESTART:
			return LINUX_ERESTART;
#endif
#ifdef ESTRPIPE
		case ESTRPIPE:
			return LINUX_ESTRPIPE;
#endif
#ifdef EUSERS
		case EUSERS:
			return LINUX_EUSERS;
#endif
#ifdef ENOTSOCK
		case ENOTSOCK:
			return LINUX_ENOTSOCK;
#endif
#ifdef EDESTADDRREQ
		case EDESTADDRREQ:
			return LINUX_EDESTADDRREQ;
#endif
#ifdef EMSGSIZE
		case EMSGSIZE:
			return LINUX_EMSGSIZE;
#endif
#ifdef EPROTOTYPE
		case EPROTOTYPE:
			return LINUX_EPROTOTYPE;
#endif
#ifdef ENOPROTOOPT
		case ENOPROTOOPT:
			return LINUX_ENOPROTOOPT;
#endif
#ifdef EPROTONOSUPPORT
		case EPROTONOSUPPORT:
			return LINUX_EPROTONOSUPPORT;
#endif
#ifdef ESOCKTNOSUPPORT
		case ESOCKTNOSUPPORT:
			return LINUX_ESOCKTNOSUPPORT;
#endif
#ifdef EOPNOTSUPP
		case EOPNOTSUPP:
			return LINUX_EOPNOTSUPP;
#endif
#ifdef EPFNOSUPPORT
		case EPFNOSUPPORT:
			return LINUX_EPFNOSUPPORT;
#endif
#ifdef EAFNOSUPPORT
		case EAFNOSUPPORT:
			return LINUX_EAFNOSUPPORT;
#endif
#ifdef EADDRINUSE
		case EADDRINUSE:
			return LINUX_EADDRINUSE;
#endif
#ifdef EADDRNOTAVAIL
		case EADDRNOTAVAIL:
			return LINUX_EADDRNOTAVAIL;
#endif
#ifdef ENETDOWN
		case ENETDOWN:
			return LINUX_ENETDOWN;
#endif
#ifdef ENETUNREACH
		case ENETUNREACH:
			return LINUX_ENETUNREACH;
#endif
#ifdef ENETRESET
		case ENETRESET:
			return LINUX_ENETRESET;
#endif
#ifdef ECONNABORTED
		case ECONNABORTED:
			return LINUX_ECONNABORTED;
#endif
#ifdef ECONNRESET
		case ECONNRESET:
			return LINUX_ECONNRESET;
#endif
#ifdef ENOBUFS
		case ENOBUFS:
			return LINUX_ENOBUFS;
#endif
#ifdef EISCONN
		case EISCONN:
			return LINUX_EISCONN;
#endif
#ifdef ENOTCONN
		case ENOTCONN:
			return LINUX_ENOTCONN;
#endif
#ifdef ESHUTDOWN
		case ESHUTDOWN:
			return LINUX_ESHUTDOWN;
#endif
#ifdef ETOOMANYREFS
		case ETOOMANYREFS:
			return LINUX_ETOOMANYREFS;
#endif
#ifdef ETIMEDOUT
		case ETIMEDOUT:
			return LINUX_ETIMEDOUT;
#endif
#ifdef ECONNREFUSED
		case ECONNREFUSED:
			return LINUX_ECONNREFUSED;
#endif
#ifdef EHOSTDOWN
		case EHOSTDOWN:
			return LINUX_EHOSTDOWN;
#endif
#ifdef EHOSTUNREACH
		case EHOSTUNREACH:
			return LINUX_EHOSTUNREACH;
#endif
#ifdef EALREADY
		case EALREADY:
			return LINUX_EALREADY;
#endif
#ifdef EINPROGRESS
		case EINPROGRESS:
			return LINUX_EINPROGRESS;
#endif
#ifdef ESTALE
		case ESTALE:
			return LINUX_ESTALE;
#endif
#ifdef EUCLEAN
		case EUCLEAN:
			return LINUX_EUCLEAN;
#endif
#ifdef ENOTNAM
		case ENOTNAM:
			return LINUX_ENOTNAM;
#endif
#ifdef ENAVAIL
		case ENAVAIL:
			return LINUX_ENAVAIL;
#endif
#ifdef EISNAM
		case EISNAM:
			return LINUX_EISNAM;
#endif
#ifdef EREMOTEIO
		case EREMOTEIO:
			return LINUX_EREMOTEIO;
#endif
#ifdef EDQUOT
		case EDQUOT:
			return LINUX_EDQUOT;
#endif
#ifdef ENOMEDIUM
		case ENOMEDIUM:
			return LINUX_ENOMEDIUM;
#endif
#ifdef EMEDIUMTYPE
		case EMEDIUMTYPE:
			return LINUX_EMEDIUMTYPE;
#endif
#ifdef ECANCELED
		case ECANCELED:
			return LINUX_ECANCELED;
#endif
#ifdef ENOKEY
		case ENOKEY:
			return LINUX_ENOKEY;
#endif
#ifdef EKEYEXPIRED
		case EKEYEXPIRED:
			return LINUX_EKEYEXPIRED;
#endif
#ifdef EKEYREVOKED
		case EKEYREVOKED:
			return LINUX_EKEYREVOKED;
#endif
#ifdef EKEYREJECTED
		case EKEYREJECTED:
			return LINUX_EKEYREJECTED;
#endif
#ifdef EOWNERDEAD
		case EOWNERDEAD:
			return LINUX_EOWNERDEAD;
#endif
#ifdef ENOTRECOVERABLE
		case ENOTRECOVERABLE:
			return LINUX_ENOTRECOVERABLE;
#endif
#ifdef ERFKILL
		case ERFKILL:
			return LINUX_ERFKILL;
#endif
#ifdef EHWPOISON
		case EHWPOISON:
			return LINUX_EHWPOISON;
#endif
#ifndef __linux__
#ifdef ENOTSUP
		case ENOTSUP:
			return LINUX_ENOTSUP;
#endif
#endif
		default:
        // return EINVAL instead
			return LINUX_EINVAL;
	}
}

#endif
