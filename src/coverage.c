#include "coverage.h"

#ifdef COVERAGE

#define open open_
#define access access_
#define fcntl fcntl_

#include "tls.h"

#include <errno.h>

#undef open
#undef access
#undef fcntl

#define FILE int

void __gcov_flush();

void coverage_flush(void)
{
	__gcov_flush();
}

// stub definitions of functions libgcov requires

int *__errno_location(void)
{
	return &get_thread_storage()->coverage.err;
}

#define SET_ERRNO(expr) ({ \
	__typeof__(expr) temporary_set_errno = expr; \
	if (temporary_set_errno < 0) { \
		*__errno_location() = -temporary_set_errno; \
		temporary_set_errno = -1; \
	} \
	temporary_set_errno; \
})

int open(const char *path, int flags, mode_t mode)
{
	return SET_ERRNO(fs_open(path, flags, mode));
}

int close(int fd)
{
	return SET_ERRNO(fs_close(fd));
}

int fcntl(int fd, int cmd, uintptr_t arg)
{
	return SET_ERRNO(fs_fcntl(fd, cmd, arg));
}

int access(const char *path, mode_t mode)
{
	return SET_ERRNO(fs_access(path, mode));
}

int mkdir(const char *path, mode_t mode)
{
	return SET_ERRNO(fs_mkdir(path, mode));
}

char *getenv(__attribute__((unused)) const char *name)
{
	return NULL;
}

long int strtol(__attribute__((unused)) const char *str, __attribute__((unused)) char **endptr, __attribute__((unused)) int base)
{
	return 0;
}

int __popcountdi2(unsigned long a)
{
	// don't call the intrinsic, since it calls back into __popcountdi2!
	int count = 0;
	for (; a; count++) {
		a &= a - 1;
	}
	return count;
}

int getpid(void)
{
	return SET_ERRNO(fs_getpid());
}

static int decode_flags_from_mode(const char *mode)
{
	if (mode[0] == '\0') {
		return -1;
	}
	bool has_plus = false;
	for (int i = 1; mode[i]; i++) {
		switch (mode[i]) {
			case '+':
				has_plus = true;
				break;
			case '\0':
				break;
			default:
				return -1;
		}
	}
	switch (mode[0]) {
		case 'r':
			return has_plus ? O_RDWR : O_RDONLY;
		case 'w':
			return has_plus ? O_RDWR|O_TRUNC|O_CREAT : O_WRONLY|O_TRUNC|O_CREAT;
		case 'a':
			return has_plus ? O_RDWR|O_APPEND|O_CREAT : O_WRONLY|O_APPEND;
		default:
			return -1;
	}
}

static FILE __stderr = 2;

FILE *stderr = &__stderr;

FILE *fopen(const char *filename, const char *mode)
{
	int flags = decode_flags_from_mode(mode);
	if (flags < 0) {
		*__errno_location() = EINVAL;
		return NULL;
	}
	int fd = SET_ERRNO(fs_open(filename, flags, 0644));
	if (fd == -1) {
		return NULL;
	}
	FILE *result = malloc(sizeof(FILE));
	*result = fd;
	return result;
}

int fclose(FILE *stream)
{
	if (stream) {
		fs_close(*stream);
		free(stream);
	}
	return 0;
}

FILE *fdopen(int fd, __attribute__((unused)) const char *mode)
{
	FILE *result = malloc(sizeof(fd));
	*result = fd;
	return result;
}

size_t fwrite(const void *ptr, size_t size, size_t count, FILE *stream)
{
	int result = fs_write(*stream, ptr, size * count);
	if (result > 0) {
		result /= size;
	}
	return SET_ERRNO(result);
}

size_t fread(void *ptr, size_t size, size_t count, FILE *stream)
{
	int result = fs_read(*stream, ptr, size * count);
	if (result > 0) {
		result /= size;
	}
	return SET_ERRNO(result);
}

int fseek(FILE *stream, long int offset, int origin)
{
	return SET_ERRNO(fs_lseek(*stream, offset, origin));
}

long int ftell(FILE * stream)
{
	return SET_ERRNO(fs_lseek(*stream, 0, SEEK_CUR));
}

void setbuf(__attribute__((unused)) FILE * stream, __attribute__((unused)) char * buffer)
{
}

int __fprintf_chk(FILE *stream, __attribute__((unused)) int flag, const char *format)
{
	// TODO: support formatting
	return fwrite(format, fs_strlen(format), 1, stream);
}

int __vfprintf_chk(FILE *stream, __attribute__((unused)) int flag, const char *format, __attribute__((unused)) void *ap)
{
	// TODO: support formatting
	return fwrite(format, fs_strlen(format), 1, stream);
}

#else
void coverage_flush(void)
{
}
#endif
