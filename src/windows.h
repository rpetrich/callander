#ifndef AXON_WINDOWS_H
#define AXON_WINDOWS_H

#include "axon.h"
#include "freestanding.h"
#include "linux.h"
#include "proxy.h"

#include <stdint.h>

typedef uint32_t WINDOWS_DWORD;

#define WINDOWS_FILE_READ_ATTRIBUTES 0x80
#define WINDOWS_DELETE 0x10000
#define WINDOWS_GENERIC_ALL 0x10000000
#define WINDOWS_GENERIC_EXECUTE 0x20000000
#define WINDOWS_GENERIC_WRITE 0x40000000
#define WINDOWS_GENERIC_READ 0x80000000

#define WINDOWS_FILE_SHARE_READ 0x00000001
#define WINDOWS_FILE_SHARE_WRITE 0x00000002
#define WINDOWS_FILE_SHARE_DELETE 0x00000004

#define WINDOWS_CREATE_NEW 1
#define WINDOWS_CREATE_ALWAYS 2
#define WINDOWS_OPEN_EXISTING 3
#define WINDOWS_OPEN_ALWAYS 4
#define WINDOWS_TRUNCATE_EXISTING 5

#define WINDOWS_FILE_ATTRIBUTE_READONLY 0x1
#define WINDOWS_FILE_ATTRIBUTE_HIDDEN 0x2
#define WINDOWS_FILE_ATTRIBUTE_SYSTEM 0x4
#define WINDOWS_FILE_ATTRIBUTE_DIRECTORY 0x10
#define WINDOWS_FILE_ATTRIBUTE_ARCHIVE 0x20
#define WINDOWS_FILE_ATTRIBUTE_DEVICE 0x40
#define WINDOWS_FILE_ATTRIBUTE_NORMAL 0x80
#define WINDOWS_FILE_ATTRIBUTE_TEMPORARY 0x100
#define WINDOWS_FILE_ATTRIBUTE_SPARSE_FILE 0x200
#define WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT 0x400
#define WINDOWS_FILE_ATTRIBUTE_COMPRESSED 0x800
#define WINDOWS_FILE_ATTRIBUTE_OFFLINE 0x1000

#define WINDOWS_FILE_FLAG_BACKUP_SEMANTICS 0x02000000

#define WINDOWS_FILE_BEGIN 0
#define WINDOWS_FILE_CURRENT 1
#define WINDOWS_FILE_END 2

#define WINDOWS_INVALID_HANDLE_VALUE ((void *)(long long)-1)

#define WINDOWS_MAX_PATH 260

#define WINDOWS_MEM_COMMIT 0x1000
#define WINDOWS_MEM_RESERVE 0x2000
#define WINDOWS_MEM_DECOMMIT 0x4000
#define WINDOWS_MEM_RELEASE 0x8000

#define WINDOWS_PAGE_NOACCESS 0x1
#define WINDOWS_PAGE_READONLY 0x2
#define WINDOWS_PAGE_READWRITE 0x4
#define WINDOWS_PAGE_EXECUTE 0x10
#define WINDOWS_PAGE_EXECUTE_READ 0x20
#define WINDOWS_PAGE_EXECUTE_READWRITE 0x40

typedef int WINDOWS_BOOL;
typedef uint8_t WINDOWS_BOOLEAN;

typedef void *WINDOWS_HANDLE;

typedef struct WINDOWS__FILETIME
{
	WINDOWS_DWORD dwLowDateTime;
	WINDOWS_DWORD dwHighDateTime;
} WINDOWS_FILETIME;

typedef struct WINDOWS__BY_HANDLE_FILE_INFORMATION
{
	WINDOWS_DWORD dwFileAttributes;
	WINDOWS_FILETIME ftCreationTime;
	WINDOWS_FILETIME ftLastAccessTime;
	WINDOWS_FILETIME ftLastWriteTime;
	WINDOWS_DWORD dwVolumeSerialNumber;
	WINDOWS_DWORD nFileSizeHigh;
	WINDOWS_DWORD nFileSizeLow;
	WINDOWS_DWORD nNumberOfLinks;
	WINDOWS_DWORD nFileIndexHigh;
	WINDOWS_DWORD nFileIndexLow;
} WINDOWS_BY_HANDLE_FILE_INFORMATION;

typedef struct WINDOWS__SECURITY_ATTRIBUTES
{
	WINDOWS_DWORD nLength;
	void *lpSecurityDescriptor;
	WINDOWS_BOOL bInheritHandle;
} WINDOWS_SECURITY_ATTRIBUTES;

typedef struct WINDOWS__CREATEFILE2_EXTENDED_PARAMETERS
{
	WINDOWS_DWORD dwSize;
	WINDOWS_DWORD dwFileAttributes;
	WINDOWS_DWORD dwFileFlags;
	WINDOWS_DWORD dwSecurityQosFlags;
	WINDOWS_SECURITY_ATTRIBUTES *lpSecurityAttributes;
	WINDOWS_HANDLE hTemplateFile;
} WINDOWS_CREATEFILE2_EXTENDED_PARAMETERS;

typedef struct WINDOWS__WIN32_FIND_DATAW
{
	WINDOWS_DWORD dwFileAttributes;
	WINDOWS_FILETIME ftCreationTime;
	WINDOWS_FILETIME ftLastAccessTime;
	WINDOWS_FILETIME ftLastWriteTime;
	WINDOWS_DWORD nFileSizeHigh;
	WINDOWS_DWORD nFileSizeLow;
	WINDOWS_DWORD dwReserved0;
	WINDOWS_DWORD dwReserved1;
	uint16_t cFileName[WINDOWS_MAX_PATH];
	uint16_t cAlternateFileName[14];
	WINDOWS_DWORD dwFileType; // Obsolete. Do not use.
	WINDOWS_DWORD dwCreatorType; // Obsolete. Do not use
	uint16_t wFinderFlags; // Obsolete. Do not use
} WINDOWS_WIN32_FIND_DATAW;

typedef struct WINDOWS_FILE_RENAME_INFO
{
	union {
		WINDOWS_BOOLEAN ReplaceIfExists;
		WINDOWS_DWORD Flags;
	} DUMMYUNIONNAME;
	WINDOWS_BOOLEAN ReplaceIfExists;
	WINDOWS_HANDLE RootDirectory;
	WINDOWS_DWORD FileNameLength;
	uint16_t FileName[1];
} WINDOWS_FILE_RENAME_INFO;

typedef enum WINDOWS__FILE_INFO_BY_HANDLE_CLASS
{
	WINDOWS_FileBasicInfo,
	WINDOWS_FileStandardInfo,
	WINDOWS_FileNameInfo,
	WINDOWS_FileRenameInfo,
	WINDOWS_FileDispositionInfo,
	WINDOWS_FileAllocationInfo,
	WINDOWS_FileEndOfFileInfo,
	WINDOWS_FileStreamInfo,
	WINDOWS_FileCompressionInfo,
	WINDOWS_FileAttributeTagInfo,
	WINDOWS_FileIdBothDirectoryInfo,
	WINDOWS_FileIdBothDirectoryRestartInfo,
	WINDOWS_FileIoPriorityHintInfo,
	WINDOWS_FileRemoteProtocolInfo,
	WINDOWS_FileFullDirectoryInfo,
	WINDOWS_FileFullDirectoryRestartInfo,
	WINDOWS_FileStorageInfo,
	WINDOWS_FileAlignmentInfo,
	WINDOWS_FileIdInfo,
	WINDOWS_FileIdExtdDirectoryInfo,
	WINDOWS_FileIdExtdDirectoryRestartInfo,
	WINDOWS_FileDispositionInfoEx,
	WINDOWS_FileRenameInfoEx,
	WINDOWS_FileCaseSensitiveInfo,
	WINDOWS_FileNormalizedNameInfo,
	WINDOWS_MaximumFileInfoByHandleClass
} WINDOWS_FILE_INFO_BY_HANDLE_CLASS;

intptr_t translate_windows_error(intptr_t result);
intptr_t translate_winsock_error(intptr_t result);

#define PROXY_WINDOWS_CALL(kind, module, name, ...)                                                             \
	({                                                                                                          \
		static intptr_t name;                                                                                   \
		ERROR("windows call to " #name);                                                                        \
		intptr_t windows_result = PROXY_CALL(kind, get_windows_function(&name, #module, #name), ##__VA_ARGS__); \
		if (windows_result < 0) {                                                                               \
			ERROR("error is", -(intptr_t)windows_result);                                                       \
		} else {                                                                                                \
			ERROR("result is", (uintptr_t)windows_result);                                                      \
		}                                                                                                       \
		ERROR_FLUSH();                                                                                          \
		windows_result;                                                                                         \
	})

#define PROXY_WIN32_CALL(module, name, ...) PROXY_WINDOWS_CALL(TARGET_NR_WIN32_CALL, module, name, ##__VA_ARGS__)
#define PROXY_WIN32_BOOL_CALL(module, name, ...) PROXY_WINDOWS_CALL(TARGET_NR_WIN32_BOOL_CALL, module, name, ##__VA_ARGS__)
#define PROXY_WINSOCK_CALL(module, name, ...) PROXY_WINDOWS_CALL(TARGET_NR_WINSOCK_CALL, module, name, ##__VA_ARGS__)
#define PROXY_WINSOCK_HANDLE_CALL(module, name, ...) PROXY_WINDOWS_CALL(TARGET_NR_WINSOCK_HANDLE_CALL, module, name, ##__VA_ARGS__)

inline static proxy_arg get_windows_function(intptr_t *cached, const char *module, const char *name)
{
	intptr_t result = *cached;
	if (UNLIKELY(result == 0)) {
		hello_message *hello = proxy_get_hello_message();
		intptr_t handle = PROXY_CALL(TARGET_NR_CALL, proxy_value(hello->windows.GetModuleHandleA), proxy_string(module));
		if (handle == -1) {
			DIE("could not find module", module);
		}
		result = PROXY_CALL(TARGET_NR_CALL, proxy_value(hello->windows.GetProcAddress), proxy_value(handle), proxy_string(name));
		if (result == 0) {
			DIE("could not find procedure", name);
		}
		*cached = result;
	}
	return proxy_value(result);
}

static inline const uint16_t *translate_windows_wide_path(const char *path, uint16_t out_path[PATH_MAX])
{
	if (*path != '/') {
		*out_path = '\0';
		return out_path;
	}
	path++;
	int i = 0;
	for (; *path != '\0'; i++, path++) {
		out_path[i] = *path == '/' ? '\\' : *path;
	}
	if (path[-1] == '\\') {
		i--;
	}
	out_path[i] = '\0';
	return out_path;
}

static inline const char *translate_windows_path(const char *path, char out_path[PATH_MAX])
{
	if (*path != '/') {
		*out_path = '\0';
		return out_path;
	}
	path++;
	int i = 0;
	for (; *path != '\0'; i++, path++) {
		out_path[i] = *path == '/' ? '\\' : *path;
	}
	if (path[-1] == '\\') {
		i--;
	}
	out_path[i] = '\0';
	return out_path;
}

__attribute__((always_inline)) static inline intptr_t translate_windows_result(intptr_t result)
{
	if (UNLIKELY(result < 0)) {
		return translate_windows_error(-result);
	}
	return result;
}

__attribute__((always_inline)) static inline intptr_t translate_winsock_result(intptr_t result)
{
	if (UNLIKELY(result < 0)) {
		return translate_winsock_error(-result);
	}
	return result;
}

static inline struct timespec windows_filetime_to_timespec(WINDOWS_FILETIME time)
{
	uint64_t hundo_nanos = ((uint64_t)time.dwHighDateTime << 32) | time.dwLowDateTime;
	return (struct timespec){
		.tv_sec = (hundo_nanos / 10000000) - 11644473600,
		.tv_nsec = (hundo_nanos % 10000000) * 100,
	};
}

struct fs_stat translate_windows_by_handle_file_information(WINDOWS_BY_HANDLE_FILE_INFORMATION info);
void translate_windows_by_handle_file_information_to_statx(struct linux_statx *result, WINDOWS_BY_HANDLE_FILE_INFORMATION info, unsigned int mask);

static inline WINDOWS_DWORD translate_open_flags_to_windows_desired_access(int flags)
{
	switch (flags & O_ACCMODE) {
		case O_RDWR:
			return WINDOWS_GENERIC_READ | WINDOWS_GENERIC_WRITE;
		case O_RDONLY:
			return WINDOWS_GENERIC_READ;
		case O_WRONLY:
			return WINDOWS_GENERIC_WRITE;
		default:
			return 0;
	}
}

static inline WINDOWS_DWORD translate_prot_to_windows_protect(int prot)
{
	switch (prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) {
		case PROT_NONE:
			return WINDOWS_PAGE_NOACCESS;
		case PROT_READ:
			return WINDOWS_PAGE_READONLY;
		case PROT_WRITE:
		case PROT_READ | PROT_WRITE:
			return WINDOWS_PAGE_READWRITE;
		case PROT_EXEC:
			return WINDOWS_PAGE_EXECUTE;
		case PROT_EXEC | PROT_READ:
			return WINDOWS_PAGE_EXECUTE_READ;
		default:
			return WINDOWS_PAGE_EXECUTE_READWRITE;
	}
}

#endif
