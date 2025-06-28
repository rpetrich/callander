#define _GNU_SOURCE
#include "darwin.h"

#include "axon.h"

#include <errno.h>
#include <fcntl.h>

intptr_t translate_darwin_result(intptr_t result)
{
	switch (result) {
		case -1:
			return -EPERM;
		case -2:
			return -ENOENT;
		case -3:
			return -ESRCH;
		case -4:
			return -EINTR;
		case -5:
			return -EIO;
		case -6:
			return -ENXIO;
		case -7:
			return -E2BIG;
		case -8:
			return -ENOEXEC;
		case -9:
			return -EBADF;
		case -10:
			return -ECHILD;
		case -11:
			return -EDEADLK;
		case -12:
			return -ENOMEM;
		case -13:
			return -EACCES;
		case -14:
			return -EFAULT;
		case -15:
			return -ENOTBLK;
		case -16:
			return -EBUSY;
		case -17:
			return -EEXIST;
		case -18:
			return -EXDEV;
		case -19:
			return -ENODEV;
		case -20:
			return -ENOTDIR;
		case -21:
			return -EISDIR;
		case -22:
			return -EINVAL;
		case -23:
			return -ENFILE;
		case -24:
			return -EMFILE;
		case -25:
			return -ENOTTY;
		case -26:
			return -ETXTBSY;
		case -27:
			return -EFBIG;
		case -28:
			return -ENOSPC;
		case -29:
			return -ESPIPE;
		case -30:
			return -EROFS;
		case -31:
			return -EMLINK;
		case -32:
			return -EPIPE;
		case -33:
			return -EDOM;
		case -34:
			return -ERANGE;
		case -35:
			return -EAGAIN;
		case -36:
			return -EINPROGRESS;
		case -37:
			return -EALREADY;
		case -38:
			return -ENOTSOCK;
		case -39:
			return -EDESTADDRREQ;
		case -40:
			return -EMSGSIZE;
		case -41:
			return -EPROTOTYPE;
		case -42:
			return -ENOPROTOOPT;
		case -43:
			return -EPROTONOSUPPORT;
		case -44:
			return -ESOCKTNOSUPPORT;
		case -45:
			return -ENOTSUP;
		case -46:
			return -EPFNOSUPPORT;
		case -47:
			return -EAFNOSUPPORT;
		case -48:
			return -EADDRINUSE;
		case -49:
			return -EADDRNOTAVAIL;
		case -50:
			return -ENETDOWN;
		case -51:
			return -ENETUNREACH;
		case -52:
			return -ENETRESET;
		case -53:
			return -ECONNABORTED;
		case -54:
			return -ECONNRESET;
		case -55:
			return -ENOBUFS;
		case -56:
			return -EISCONN;
		case -57:
			return -ENOTCONN;
		case -58:
			return -ESHUTDOWN;
		// is there an error 59?
		case -60:
			return -ETIMEDOUT;
		case -61:
			return -ECONNREFUSED;
		case -62:
			return -ELOOP;
		case -63:
			return -ENAMETOOLONG;
		case -64:
			return -EHOSTDOWN;
		case -65:
			return -EHOSTUNREACH;
		case -66:
			return -ENOTEMPTY;
		case -67:
			// no idea what the closest return code is
			// return -EPROCLIM;
			return -EAGAIN;
		case -68:
			return -EUSERS;
		case -69:
			return -EDQUOT;
		case -70:
			return -ESTALE;
		// is there an error 71?
		case -72:
			// no idea what this does
			// return -EBADRPC;
			return -EPROTO;
		case -73:
			// no idea what this does
			// return -ERPCMISMATCH;
			return -EPROTO;
		case -74:
			// no idea what this does
			// return -EPROGUNAVAIL;
			return -EPROTO;
		case -75:
			// no idea what this does
			// return -EPROGMISMATCH;
			return -EPROTO;
		case -76:
			// no idea what this does
			// return -EPROCUNAVAIL;
			return -EPROTO;
		case -77:
			return -ENOLCK;
		case -78:
			return -ENOSYS;
		case -79:
			// no idea what the closest return code is
			// return -EFTYPE;
			return -EINVAL;
		case -80:
			// closest is EPERM, I think
			// return -EAUTH;
			return -EPERM;
		case -81:
			// closest is EPERM, I think
			// return -ENEEDAUTH;
			return -EPERM;
		case -82:
			// closest is ENODEV, I think
			// return -EPWROFF;
			return -ENODEV;
		case -83:
			// closest is ENODEV, I think
			// return -EDEVERR;
			return -ENODEV;
		case -84:
			return -EOVERFLOW;
		case -85:
			// closest is ENOEXEC, I think
			// return -EBADEXEC;
			return -ENOEXEC;
		case -86:
			// closest is ENOEXEC, I think
			// return -EBADARCH;
			return -ENOEXEC;
		case -87:
			// closest is ENOEXEC, I think
			// return -ESHLIBVERS;
			return -ENOEXEC;
		case -88:
			// closest is ENOEXEC, I think
			// return -EBADMACHO;
			return -ENOEXEC;
		case -89:
			return -ECANCELED;
		case -90:
			return -EIDRM;
		case -91:
			return -ENOMSG;
		case -92:
			return -EILSEQ;
		case -93:
			// Linux uses -ENODATA
			// return -ENOATTR;
			return -ENODATA;
		case -94:
			return -EBADMSG;
		case -95:
			return -EMULTIHOP;
		case -96:
			return -ENODATA;
		case -97:
			return -ENOLINK;
		case -98:
			return -ENOSR;
		case -99:
			return -ENOSTR;
		case -100:
			return -EPROTO;
		case -101:
			return -ETIME;
		case -102:
			return -EOPNOTSUPP;
		default:
			return result;
	}
}

int translate_at_fd_to_darwin(int fd)
{
	if (fd == AT_FDCWD) {
		return DARWIN_AT_FDCWD;
	}
	return fd;
}

int translate_open_flags_to_darwin(int flags)
{
	// O_RDONLY, OWRONLY, O_RDWR and O_ACCMODE are the same
	int result = flags & O_ACCMODE;
	if (flags & O_CREAT) {
		result |= 0x00000200;
	}
	if (flags & O_EXCL) {
		result |= 0x00000800;
	}
	if (flags & O_NOCTTY) {
		result |= 0x00020000;
	}
	if (flags & O_TRUNC) {
		result |= 0x00000400;
	}
	if (flags & O_APPEND) {
		result |= 0x00000008;
	}
	if (flags & O_NONBLOCK) {
		result |= 0x00000004;
	}
	if (flags & O_DSYNC) {
		result |= 0x00400000;
	}
	if (flags & O_ASYNC) {
		result |= 0x00000040;
	}
	if (flags & O_DIRECT) {
		// TODO: apply direct mode?
	}
	if (flags & O_LARGEFILE) {
		// do we need to do anything? I think this is 32-bit brokenness
	}
	if (flags & O_DIRECTORY) {
		result |= 0x00100000;
	}
	if (flags & O_NOFOLLOW) {
		result |= 0x20000000;
	}
	if (flags & O_NOATIME) {
		// macOS doesn't have this, but I don't think tracks atime anyway
	}
	if (flags & O_CLOEXEC) {
		result |= 0x01000000;
	}
	return result;
}

int translate_seek_whence_to_darwin(int whence)
{
	switch (whence) {
		case 4:
			return 3;
		case 3:
			return 4;
		default:
			return whence;
	}
}

static uint32_t translate_darwin_mode_ifmt(uint16_t mode)
{
	switch (mode & S_IFMT) {
		case 0010000:
			return S_IFIFO;
		case 0020000:
			return S_IFCHR;
		case 0040000:
			return S_IFDIR;
		case 0060000:
			// it's actually S_IFBLK, but linux ls fails on block devices *womp womp*
			// return S_IFBLK;
			return S_IFDIR;
		case 0100000:
			return S_IFREG;
		case 0120000:
			return S_IFLNK;
		case 0140000:
			return S_IFSOCK;
		// case 0160000:
		// 	return S_IFWHT;
		default:
			return 0;
	}
}

struct fs_stat translate_darwin_stat(struct darwin_stat stat)
{
	struct fs_stat result = {0};
	result.st_dev = stat.st_dev;
	result.st_ino = stat.st_ino;
	result.st_mode = (stat.st_mode & ~S_IFMT) | translate_darwin_mode_ifmt(stat.st_mode);
	result.st_nlink = stat.st_nlink;
	result.st_uid = stat.st_uid;
	result.st_gid = stat.st_gid;
	result.st_rdev = stat.st_rdev;
	result.st_size = stat.st_size;
	result.st_blksize = stat.st_blksize;
	result.st_blocks = stat.st_blocks;
	result.st_atime_sec = stat.st_atimespec.tv_sec;
	result.st_atime_nsec = stat.st_atimespec.tv_nsec;
	result.st_mtime_sec = stat.st_mtimespec.tv_sec;
	result.st_mtime_nsec = stat.st_mtimespec.tv_nsec;
	result.st_ctime_sec = stat.st_ctimespec.tv_sec;
	result.st_ctime_nsec = stat.st_ctimespec.tv_nsec;
	return result;
}

void translate_darwin_statx(struct linux_statx *out_statx, struct darwin_stat stat, unsigned int mask)
{
	out_statx->stx_dev_major = (stat.st_dev >> 8) & 0xff;
	out_statx->stx_dev_minor = stat.st_dev & 0xff;
	out_statx->stx_blksize = stat.st_blksize;
	unsigned int filled = 0;
	if (mask & STATX_TYPE) {
		filled |= STATX_TYPE;
	}
	if (mask & STATX_MODE) {
		filled |= STATX_MODE;
	}
	if (mask & (STATX_MODE | STATX_TYPE)) {
		out_statx->stx_mode = (stat.st_mode & ~S_IFMT) | translate_darwin_mode_ifmt(stat.st_mode);
	}
	if (mask & STATX_NLINK) {
		filled |= STATX_NLINK;
		out_statx->stx_nlink = stat.st_nlink;
	}
	if (mask & STATX_UID) {
		filled |= STATX_UID;
		out_statx->stx_uid = stat.st_uid;
	}
	if (mask & STATX_GID) {
		filled |= STATX_GID;
		out_statx->stx_gid = stat.st_gid;
	}
	if (mask & STATX_ATIME) {
		filled |= STATX_ATIME;
		out_statx->stx_atime.tv_sec = stat.st_atimespec.tv_sec;
		out_statx->stx_atime.tv_nsec = stat.st_atimespec.tv_nsec;
	}
	if (mask & STATX_MTIME) {
		filled |= STATX_MTIME;
		out_statx->stx_mtime.tv_sec = stat.st_mtimespec.tv_sec;
		out_statx->stx_mtime.tv_nsec = stat.st_mtimespec.tv_nsec;
	}
	if (mask & STATX_CTIME) {
		filled |= STATX_CTIME;
		out_statx->stx_ctime.tv_sec = stat.st_ctimespec.tv_sec;
		out_statx->stx_ctime.tv_nsec = stat.st_ctimespec.tv_nsec;
	}
	if (mask & STATX_INO) {
		filled |= STATX_INO;
		out_statx->stx_ino = stat.st_ino;
	}
	if (mask & STATX_SIZE) {
		filled |= STATX_SIZE;
		out_statx->stx_size = stat.st_size;
	}
	if (mask & STATX_BLOCKS) {
		filled |= STATX_BLOCKS;
		out_statx->stx_blocks = stat.st_blocks;
	}
	out_statx->stx_mask = filled;
#if 0
	if (mask & STATX_BTIME) {
		// using ctime instead
		out_statx->stx_btime.tv_sec = stat.st_ctimespec.tv_sec;
		out_statx->stx_btime.tv_nsec = stat.st_ctimespec.tv_nsec;
	}
	if (mask & STATX_MNT_ID) {
		out_statx->stx_mnt_id = 0;
	}
#ifdef STATX_DIOALIGN
	if (mask & STATX_DIOALIGN) {
		out_statx->stx_dio_mem_align = 0;
		out_statx->stx_dio_offset_align = 0;
	}
#endif
#endif
}

int translate_at_flags_to_darwin(int flags)
{
	int result = 0;
	if (flags & AT_EACCESS) {
		flags &= AT_SYMLINK_NOFOLLOW;
		result |= 0x0010;
	}
	if (flags & AT_SYMLINK_NOFOLLOW) {
		flags &= AT_SYMLINK_NOFOLLOW;
		result |= 0x0020;
	}
	if (flags & AT_EMPTY_PATH) {
		flags &= AT_EMPTY_PATH;
		result |= 0x0400;
	}
	return result;
}
