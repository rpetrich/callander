// because compilers can generate calls to one of these functions even in
// freestanding, provide simple implementations of them

// do some define hacks so that we can provide our own memcpy
#define memcpy memcpy_
#include <string.h>
#undef memcpy

#include "defaultlibs.h"

#include "freestanding.h"
#include "axon.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>

#ifdef STANDALONE

struct fs_mutex malloc_lock;

__attribute__((used, visibility("hidden")))
int memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *str1 = (const unsigned char *)s1;
	const unsigned char *str2 = (const unsigned char *)s2;

	while (n-- > 0) {
		if (*str1++ != *str2++) {
			return str1[-1] < str2[-1] ? -1 : 1;
		}
	}
	return 0;
}

__attribute__((used, visibility("hidden")))
void *memset(void *s, int c, size_t n)
{
	char *buf = s;
#if 0
	ssize_t i = 0;
	if (LIKELY(c == 0)) {
		ssize_t n_trunc = (ssize_t)(n & ~((sizeof(uint64_t) * 2) - 1));
		for (; i < n_trunc; i += sizeof(uint64_t) * 2) {
			*(uint64_t *)&buf[i] = 0;
			*(uint64_t *)&buf[i+sizeof(uint64_t)] = 0;
		}
	}
	for (; i < (ssize_t)n; i++) {
		buf[i] = c;
	}
#else
	char *end = &((char *)s)[n];
	if (LIKELY(c == 0)) {
		char *end_trunc = &buf[(ssize_t)(n & ~((sizeof(uint64_t) * 2) - 1))];
		while (buf != end_trunc) {
			*(uint64_t *)buf = 0;
			buf += sizeof(uint64_t);
			*(uint64_t *)buf = 0;
			buf += sizeof(uint64_t);
		}
	}
	while (buf != end) {
		*buf = c;
		buf++;
	}
#endif
	return s;
}

__attribute__((used, visibility("hidden")))
void *__memset_chk(void *dest, int c, size_t len, size_t destlen)
{
	if (UNLIKELY(len > destlen)) {
		abort();
	}
	return memset(dest, c, len);
}

__attribute__((__nothrow__, used))
void *memcpy(void *__restrict destination, const void *__restrict source, size_t num)
{
	return fs_memcpy(destination, source, num);
}

__attribute__((used, visibility("hidden")))
void *__memcpy_chk(void *__restrict destination, const void *__restrict source, size_t num, size_t destlen)
{
	if (UNLIKELY(num > destlen)) {
		abort();
	}
	return memcpy(destination, source, num);
}

__attribute__((used, visibility("hidden")))
void *memmove(void *destination, const void *source, size_t num)
{
	return fs_memmove(destination, source, num);
}

__attribute__((used, visibility("hidden")))
size_t strlen(const char *str)
{
	return fs_strlen(str);
}

__attribute__((used, visibility("hidden")))
char *strdup(const char *str)
{
	size_t size = fs_strlen(str) + 1;
	char *result = malloc(size);
	return fs_memcpy(result, str, size);
}

__attribute__((used, visibility("hidden")))
char *strcpy(char *destination, const char *source)
{
	char *result = destination;
	while ((*destination++ = *source++)) {
	}
	return result;
}

__attribute__((used, visibility("hidden")))
char *__strcpy_chk(char *destination, const char *source, size_t destlen)
{
	char *result = destination;
	while ((*destination++ = *source++)) {
		if (UNLIKELY(destination == &result[destlen-1])) {
			abort();
		}
	}
	return result;
}

__attribute__((used, visibility("hidden")))
char *strcat(char *destination, const char *source)
{
	size_t destlen = fs_strlen(destination);
	size_t srclen = fs_strlen(source);
	memcpy(&destination[destlen], source, srclen+1);
	return destination;
}

__attribute__((used, visibility("hidden")))
void *memchr(const void *str, int c, size_t n)
{
	return (void *)fs_memchr(str, c, n);
}

__attribute__((used, visibility("hidden")))
void abort(void)
{
	ERROR_FLUSH();
	struct fs_sigset_t set = { 0 };
	fs_sigaddset(&set, SIGABRT);
	intptr_t result = fs_rt_sigprocmask(SIG_UNBLOCK, &set, NULL, sizeof(struct fs_sigset_t));
	if (result != 0) {
		fs_exit(127);
	}
	result = fs_tkill(fs_gettid(), SIGABRT);
	if (result != 0) {
		fs_exit(127);
	}
	__builtin_unreachable();
}

__attribute__((used, visibility("hidden")))
void __assert_fail(__attribute__((unused)) const char *expr, __attribute__((unused)) const char *file, __attribute__((unused)) unsigned int line, __attribute__((unused)) const char *function)
{
	struct iovec vec[8];
	vec[0].iov_base = "axon: assertion failed at ";
	vec[0].iov_len = sizeof("axon: assertion failed at ")-1;
	vec[1].iov_base = (void *)expr;
	vec[1].iov_len = strlen(expr);
	vec[2].iov_base = " in ";
	vec[2].iov_len = sizeof(" in ")-1;
	vec[3].iov_base = (void *)function;
	vec[3].iov_len = strlen(function);
	vec[4].iov_base = " (";
	vec[4].iov_len = sizeof(" (")-1;
	vec[5].iov_base = (void *)file;
	vec[5].iov_len = strlen(file);
	vec[6].iov_base = (void *)file;
	vec[6].iov_len = strlen(file);
	char buf[33];
	buf[0] = ':';
	int size = fs_itoa(line, &buf[1]);
	buf[size+1] = ')';
	buf[size+2] = '\n';
	vec[7].iov_base = buf;
	vec[7].iov_len = size + 3;
	ERROR_WRITEV(vec, 8);
	abort();
	__builtin_unreachable();
}

#ifdef STACK_PROTECTOR
__attribute__((used))
#endif
void __stack_chk_fail(void)
{
	abort();
	__builtin_unreachable();
}

long int __fdelt_chk(long int fd)
{
	if (fd < 0 || fd >= FD_SETSIZE) {
		abort();
		__builtin_unreachable();
	}
	return fd / NFDBITS;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *result = fs_mmap(addr, length, prot, flags, fd, offset);
	return fs_is_map_failed(result) ? MAP_FAILED : result;
}

int munmap(void *addr, size_t length)
{
	return fs_munmap(addr, length) ? -1 : 0;
}

void sched_yield(void)
{
	fs_sched_yield();
}

void* dlmalloc(size_t);
__attribute__((used, visibility("hidden")))
void *malloc(size_t size)
{
	fs_mutex_lock(&malloc_lock);
	void *result = dlmalloc(size);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

void* dlcalloc(size_t, size_t);
__attribute__((used, visibility("hidden")))
void *calloc(size_t count, size_t size)
{
	fs_mutex_lock(&malloc_lock);
	void *result = dlcalloc(count, size);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

void  dlfree(void*);
__attribute__((used, visibility("hidden")))
void free(void *ptr)
{
	if (ptr) {
		fs_mutex_lock(&malloc_lock);
		dlfree(ptr);
		fs_mutex_unlock(&malloc_lock);
	}
}

size_t dlmalloc_usable_size(void*);
size_t malloc_size(const void *ptr)
{
	if (ptr == NULL) {
		return 0;
	}
	fs_mutex_lock(&malloc_lock);
	size_t result = dlmalloc_usable_size((void *)ptr);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

size_t malloc_good_size(size_t size)
{
	// currently this does nothing, but could pad
	return size;
}

void* dlrealloc(void*, size_t);
__attribute__((used, visibility("hidden")))
void *realloc(void *ptr, size_t size)
{
	fs_mutex_lock(&malloc_lock);
	void *result = dlrealloc(ptr, size);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

int dlposix_memalign(void**, size_t, size_t);
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	fs_mutex_lock(&malloc_lock);
	int result = dlposix_memalign(memptr, alignment, size);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

void *dlmemalign(size_t, size_t);
__attribute__((used, visibility("hidden")))
void *aligned_alloc(size_t alignment, size_t size)
{
	fs_mutex_lock(&malloc_lock);
	void *result = dlmemalign(alignment, size);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

#endif

#ifdef ERRORS_ARE_BUFFERED

static char error_buffer[4096 * 64];
static atomic_size_t error_offset;

void error_writev(const struct iovec *vec, int count)
{
	for (int i = 0; i < count; i++) {
		error_write(vec[i].iov_base, vec[i].iov_len);
	}
}

void error_write(const char *buf, size_t length)
{
	size_t existing_offset = atomic_load(&error_offset);
	while (UNLIKELY(existing_offset + length > sizeof(error_buffer))) {
		error_flush();
		if (length > sizeof(error_buffer)) {
			if (fs_write_all(2, buf, length) != (intptr_t)length) {
				abort();
				__builtin_unreachable();
			}
			return;
		}
		existing_offset = atomic_load(&error_offset);
	}
	fs_memcpy(&error_buffer[existing_offset], buf, length);
	atomic_fetch_add(&error_offset, length);
}

void error_flush(void)
{
	size_t existing_offset = atomic_exchange(&error_offset, 0);
	if (existing_offset != 0) {
		if (existing_offset > sizeof(error_buffer)) {
			existing_offset = sizeof(error_buffer);
		}
		intptr_t result = fs_write_all(2, error_buffer, existing_offset);
		if (result != (intptr_t)existing_offset) {
			if (result < 0) {
				(void)fs_write(2, "failed to write errors: ", sizeof("failed to write errors: ")-1);
				const char *errorstr = fs_strerror(result);
				fs_write(2, errorstr, fs_strlen(errorstr));
				(void)fs_write(2, "\n", 1);
			} else {
				(void)fs_write(2, "failed to write errors\n", sizeof("failed to write errors\n")-1);
			}
			abort();
			__builtin_unreachable();
		}
	}
}

#endif
