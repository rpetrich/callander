#include "windows.h"

#include "axon.h"

#include <errno.h>

intptr_t translate_windows_error(intptr_t result)
{
	switch (result) {
		case 0:
			DIE("found ERROR_SUCCESS");
		case 1:
			return -EINVAL;
		case 2:
		case 3:
			return -ENOENT;
		case 4:
			return -EMFILE;
		case 5:
			return -EPERM;
		case 6:
			return -EBADF;
		case 7:
			return -EBADFD;
		case 8:
			return -ENOMEM;
		case 9:
			return -EBADFD;
		case 10:
			return -E2BIG;
		case 11:
			return -ENOEXEC;
		case 12:
			return -EFAULT;
		case 13:
			return -EBADFD;
		case 14:
			return -ENOMEM;
		case 15:
			return -ENOENT;
		case 16:
			return -EPERM;
		case 17:
			return -EXDEV;
		case 18: // ERROR_NO_MORE_FILES
			return -ENOENT;
		case 19:
			return -EPERM;
		case 20:
			return -ENOENT;
		case 21:
			return -EBUSY;
		case 87:
			return -EINVAL;
		case 487:
			return -EINVAL;
		// TODO: translate more errors
		default:
			DIE("unknown windows error: ", result);
	}
}

intptr_t translate_winsock_error(intptr_t result)
{
	switch (result) {
		case 6:
			return -EBADF;
		case 8:
			return -ENOMEM;
		case 87:
			return -EINVAL;
		case 995:
			return -ECANCELED;
		case 996:
			return -EINPROGRESS;
		case 997:
			return -EINPROGRESS;
		case 10004:
			return -EINTR;
		case 10013:
			return -EACCES;
		case 10014:
			return -EFAULT;
		case 10022:
			return -EINVAL;
		case 10024:
			return -EMFILE;
		case 10035:
			return -EWOULDBLOCK;
		case 10036:
			return -EINPROGRESS;
		case 10037:
			return -EALREADY;
		case 10039:
			return -EDESTADDRREQ;
		case 10040:
			return -EMSGSIZE;
		case 10041:
			return -EPROTOTYPE;
		case 10042:
			return -ENOPROTOOPT;
		case 10043:
			return -EPROTONOSUPPORT;
		case 10044:
			return -ESOCKTNOSUPPORT;
		case 10045:
			return -EOPNOTSUPP;
		case 10046:
			return -EPFNOSUPPORT;
		case 10047:
			return -EAFNOSUPPORT;
		case 10048:
			return -EADDRINUSE;
		case 10049:
			return -EADDRNOTAVAIL;
		case 10050:
			return -ENETDOWN;
		case 10051:
			return -ENETUNREACH;
		case 10052:
			return -ENETRESET;
		case 10053:
			return -ECONNABORTED;
		case 10054:
			return -ECONNRESET;
		case 10055:
			return -ENOBUFS;
		case 10058:
			return -ESHUTDOWN;
		case 10059:
			return -ETOOMANYREFS;
		case 10060:
			return -ETIMEDOUT;
		case 10061:
			return -ECONNREFUSED;
		case 10062:
			return -ELOOP;
		case 10063:
			return -ENAMETOOLONG;
		case 10064:
			return -EHOSTDOWN;
		case 10065:
			return -EHOSTUNREACH;
		case 10066:
			return -ENOTEMPTY;
		// case 10067:
		// 	return -EPROCLIM;
		case 10068:
			return -EUSERS;
		case 10069:
			return -EDQUOT;
		case 10070:
			return -ESTALE;
		case 10071:
			return -EREMOTE;
		// case 10091:
		// 	return -ESYSNOTREADY;
		// case 10092:
		// 	return -EVERNOTSUPPORTED;
		// case 10093:
		// 	return -ENOTINITIALISED;
		// case 10101:
		// 	return -EDISCON;
		// case 10102:
		// 	return -ENOMORE;
		case 10103:
			return -ECANCELED;
		// case 10104:
		// 	return -EINVALIDPROCTABLE;
		// case 10105:
		// 	return -EINVALIDPROVIDER;
		// case 10106:
		// 	return -EPROVIDERFAILEDINIT;
		// case 10107:
		// 	return -ESYSCALLFAILURE;
		// case 10108:
		// 	return -ESERVICE_NOT_FOUND;
		// case 10109:
		// 	return -ETYPE_NOT_FOUND;
		// case 10110:
		// 	return -ENOMORE;
		default:
			DIE("unknown winsock error: ", result);
	}
}

static mode_t mode_for_file_attributes(WINDOWS_DWORD fileAttributes)
{
	mode_t result;
	if (fileAttributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY) {
		result = S_IFDIR | S_IXOTH | S_IXGRP | S_IXUSR;
	} else if (fileAttributes & WINDOWS_FILE_ATTRIBUTE_DEVICE) {
		result = S_IFBLK;
	} else if (fileAttributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT) {
		result = S_IFLNK;
	} else {
		result = S_IFREG;
	}
	if (fileAttributes & WINDOWS_FILE_ATTRIBUTE_READONLY) {
		result |= S_IROTH | S_IRGRP | S_IRUSR;
	} else {
		result |= S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP | S_IRUSR | S_IWUSR;
	}
	return result;
}

struct fs_stat translate_windows_by_handle_file_information(WINDOWS_BY_HANDLE_FILE_INFORMATION info)
{
	struct fs_stat result = {0};
	result.st_dev = info.dwVolumeSerialNumber;
	result.st_ino = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
	result.st_mode = mode_for_file_attributes(info.dwFileAttributes);
	result.st_nlink = 1;
	result.st_uid = 0;
	result.st_gid = 0;
	result.st_rdev = 0;
	uint64_t size = (info.dwFileAttributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY) ? 4096 : (((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow);
	result.st_size = size;
	result.st_blksize = 4096;
	result.st_blocks = (size + 4095) / 4096;
	struct timespec atime = windows_filetime_to_timespec(info.ftLastAccessTime);
	result.st_atime_sec = atime.tv_sec;
	result.st_atime_nsec = atime.tv_nsec;
	struct timespec mtime = windows_filetime_to_timespec(info.ftLastWriteTime);
	result.st_mtime_sec = mtime.tv_sec;
	result.st_mtime_nsec = mtime.tv_nsec;
	struct timespec ctime = windows_filetime_to_timespec(info.ftCreationTime);
	result.st_ctime_sec = ctime.tv_sec;
	result.st_ctime_nsec = ctime.tv_nsec;
	return result;
}

void translate_windows_by_handle_file_information_to_statx(struct linux_statx *out_statx, WINDOWS_BY_HANDLE_FILE_INFORMATION info, unsigned int mask)
{
	out_statx->stx_dev_major = info.dwVolumeSerialNumber >> 16;
	out_statx->stx_dev_minor = info.dwVolumeSerialNumber;
	out_statx->stx_blksize = 4096;
	unsigned int filled = 0;
	if (mask & STATX_TYPE) {
		filled |= STATX_TYPE;
	}
	if (mask & STATX_MODE) {
		filled |= STATX_MODE;
	}
	if (mask & (STATX_MODE | STATX_TYPE)) {
		out_statx->stx_mode = mode_for_file_attributes(info.dwFileAttributes);
	}
	if (mask & STATX_NLINK) {
		filled |= STATX_NLINK;
		out_statx->stx_nlink = 1;
	}
	if (mask & STATX_UID) {
		filled |= STATX_UID;
		out_statx->stx_uid = 0;
	}
	if (mask & STATX_GID) {
		filled |= STATX_GID;
		out_statx->stx_gid = 0;
	}
	if (mask & STATX_ATIME) {
		filled |= STATX_ATIME;
		struct timespec atime = windows_filetime_to_timespec(info.ftLastAccessTime);
		out_statx->stx_atime.tv_sec = atime.tv_sec;
		out_statx->stx_atime.tv_nsec = atime.tv_nsec;
	}
	if (mask & STATX_MTIME) {
		filled |= STATX_MTIME;
		struct timespec mtime = windows_filetime_to_timespec(info.ftLastWriteTime);
		out_statx->stx_mtime.tv_sec = mtime.tv_sec;
		out_statx->stx_mtime.tv_nsec = mtime.tv_nsec;
	}
	if (mask & STATX_CTIME) {
		filled |= STATX_CTIME;
		struct timespec ctime = windows_filetime_to_timespec(info.ftCreationTime);
		out_statx->stx_ctime.tv_sec = ctime.tv_sec;
		out_statx->stx_ctime.tv_nsec = ctime.tv_nsec;
	}
	if (mask & STATX_INO) {
		filled |= STATX_INO;
		out_statx->stx_ino = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
	}
	uint64_t size = (info.dwFileAttributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY) ? 4096 : (((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow);
	if (mask & STATX_SIZE) {
		filled |= STATX_SIZE;
		out_statx->stx_size = size;
	}
	if (mask & STATX_BLOCKS) {
		filled |= STATX_BLOCKS;
		out_statx->stx_blocks = (size + 4095) / 4096;
	}
	out_statx->stx_mask = filled;
}
