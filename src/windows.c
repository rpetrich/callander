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
			return 0;
		case 19:
			return -EPERM;
		case 20:
			return -ENOENT;
		case 21:
			return -EBUSY;
		// TODO: translate more errors
		default:
			DIE("unknown windows error", result);
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
	struct fs_stat result = { 0 };
	result.st_dev = info.dwVolumeSerialNumber;
	result.st_ino = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
	result.st_mode = mode_for_file_attributes(info.dwFileAttributes);
	result.st_nlink = 0;
	result.st_uid = 0;
	result.st_gid = 0;
	result.st_rdev = 0;
	result.st_size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
	result.st_blksize = 4096;
	result.st_blocks = (result.st_size + 4095) / 4096;
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
		out_statx->stx_nlink = 0;
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
		out_statx->stx_atime.tv_sec = 0;
		out_statx->stx_atime.tv_nsec = 0;
	}
	if (mask & STATX_MTIME) {
		filled |= STATX_MTIME;
		out_statx->stx_mtime.tv_sec = 0;
		out_statx->stx_mtime.tv_nsec = 0;
	}
	if (mask & STATX_CTIME) {
		filled |= STATX_CTIME;
		out_statx->stx_ctime.tv_sec = 0;
		out_statx->stx_ctime.tv_nsec = 0;
	}
	if (mask & STATX_INO) {
		filled |= STATX_INO;
		out_statx->stx_ino = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
	}
	if (mask & STATX_SIZE) {
		filled |= STATX_SIZE;
		out_statx->stx_size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
	}
	if (mask & STATX_BLOCKS) {
		filled |= STATX_BLOCKS;
		out_statx->stx_blocks = ((((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow) + 4095) / 4096;
	}
}
