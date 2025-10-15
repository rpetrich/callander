// because compilers can generate calls to one of these functions even in
// freestanding, provide simple implementations of them

// do some define hacks so that we can provide our own memcpy
#define memcpy memcpy_
#include <string.h>
#undef memcpy

#include "defaultlibs.h"

#include "axon.h"
#include "freestanding.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>

#ifdef STANDALONE

struct fs_mutex malloc_lock;

__attribute__((used, visibility("hidden"))) int memcmp(const void *s1, const void *s2, size_t n)
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

__attribute__((used, visibility("hidden"))) void *memset(void *s, int c, size_t n)
{
	if (LIKELY(c == '\0')) {
		return fs_memset(s, '\0', n);
	}
	return fs_memset(s, c, n);
}

__attribute__((used, visibility("hidden"))) void *__memset_chk(void *dest, int c, size_t len, size_t destlen)
{
	if (UNLIKELY(len > destlen)) {
		abort();
	}
	return memset(dest, c, len);
}

__attribute__((__nothrow__, used)) void *memcpy(void *__restrict destination, const void *__restrict source, size_t num)
{
	fs_memcpy(destination, source, num);
	return destination;
}

__attribute__((used, visibility("hidden"))) void *__memcpy_chk(void *__restrict destination, const void *__restrict source, size_t num, size_t destlen)
{
	if (UNLIKELY(num > destlen)) {
		abort();
	}
	return memcpy(destination, source, num);
}

__attribute__((used, visibility("hidden"))) void *memmove(void *destination, const void *source, size_t num)
{
	fs_memmove(destination, source, num);
	return destination;
}

__attribute__((used, visibility("hidden"))) size_t strlen(const char *str)
{
	return fs_strlen(str);
}

__attribute__((used, visibility("hidden"))) char *strdup(const char *str)
{
	size_t size = fs_strlen(str) + 1;
	char *result = malloc(size);
	return memcpy(result, str, size);
}

__attribute__((noinline)) __attribute__((visibility("default")))
void before(size_t size)
{
	(void)size;
	__asm__ __volatile__("" : : : "memory");
}

__attribute__((noinline)) __attribute__((visibility("default")))
void after(void)
{
	__asm__ __volatile__("" : : : "memory");
}

__attribute__((used, visibility("hidden"))) char *strcpy(char *destination, const char *source)
{
	char *result = destination;
	while ((*destination++ = *source++)) {
	}
	return result;
}

__attribute__((used, visibility("hidden"))) char *__strcpy_chk(char *destination, const char *source, size_t destlen)
{
	char *result = destination;
	while ((*destination++ = *source++)) {
		if (UNLIKELY(destination == &result[destlen - 1])) {
			abort();
		}
	}
	return result;
}

__attribute__((used, visibility("hidden"))) char *strcat(char *destination, const char *source)
{
	size_t destlen = fs_strlen(destination);
	size_t srclen = fs_strlen(source);
	memcpy(&destination[destlen], source, srclen + 1);
	return destination;
}

__attribute__((used, visibility("hidden"))) void *memchr(const void *str, int c, size_t n)
{
	return (void *)fs_memchr(str, c, n);
}

[[gnu::cold]] [[gnu::noinline]]
__attribute__((used, visibility("hidden"))) void abort(void)
{
	ERROR_FLUSH();
	struct fs_sigset_t set = {0};
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

__attribute__((used, visibility("hidden"))) void __assert_fail(__attribute__((unused)) const char *expr, __attribute__((unused)) const char *file, __attribute__((unused)) unsigned int line, __attribute__((unused)) const char *function)
{
	ERROR_NOPREFIX(PRODUCT_NAME, "assertion failed at ", expr, " in ", function, " (", file, ":", line, ")");
	abort();
	__builtin_unreachable();
}

#ifdef STACK_PROTECTOR
__attribute__((used))
#endif
void
__stack_chk_fail(void)
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

void *dlmalloc(size_t);
__attribute__((used, visibility("hidden"))) void *malloc(size_t size)
{
	fs_mutex_lock(&malloc_lock);
	void *result = dlmalloc(size);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

void *dlcalloc(size_t, size_t);
__attribute__((used, visibility("hidden"))) void *calloc(size_t count, size_t size)
{
	fs_mutex_lock(&malloc_lock);
	void *result = dlcalloc(count, size);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

void dlfree(void *);
__attribute__((used, visibility("hidden"))) void free(void *ptr)
{
	if (ptr) {
		fs_mutex_lock(&malloc_lock);
		dlfree(ptr);
		fs_mutex_unlock(&malloc_lock);
	}
}

size_t dlmalloc_usable_size(void *);
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

void *dlrealloc(void *, size_t);
__attribute__((used, visibility("hidden"))) void *realloc(void *ptr, size_t size)
{
	fs_mutex_lock(&malloc_lock);
	void *result = dlrealloc(ptr, size);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

int dlposix_memalign(void **, size_t, size_t);
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	fs_mutex_lock(&malloc_lock);
	int result = dlposix_memalign(memptr, alignment, size);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

void *dlmemalign(size_t, size_t);
__attribute__((used, visibility("hidden"))) void *aligned_alloc(size_t alignment, size_t size)
{
	fs_mutex_lock(&malloc_lock);
	void *result = dlmemalign(alignment, size);
	fs_mutex_unlock(&malloc_lock);
	return result;
}

__attribute__((used)) __uint128_t __ashlti3(__uint128_t a, int b)
{
	const int bits_in_dword = (int)(sizeof(uint64_t) * 8);
	union {
		__uint128_t all;
		struct
		{
			uint64_t low;
			uint64_t high;
		} s;
	} input, result;
	input.all = a;
	if (b & bits_in_dword) /* bits_in_dword <= b < bits_in_tword */ {
		result.s.low = 0;
		result.s.high = input.s.low << (b - bits_in_dword);
	} else /* 0 <= b < bits_in_dword */ {
		if (b == 0)
			return a;
		result.s.low = input.s.low << b;
		result.s.high = (input.s.high << b) | (input.s.low >> (bits_in_dword - b));
	}
	return result.all;
}

__attribute__((used)) __uint128_t __lshrti3(__uint128_t a, int b)
{
	const int bits_in_dword = (int)(sizeof(uint64_t) * 8);
	union {
		__uint128_t all;
		struct
		{
			uint64_t low;
			uint64_t high;
		} s;
	} input, result;
	input.all = a;
	if (b & bits_in_dword) /* bits_in_dword <= b < bits_in_tword */ {
		result.s.high = 0;
		result.s.low = input.s.high >> (b - bits_in_dword);
	} else /* 0 <= b < bits_in_dword */ {
		if (b == 0)
			return a;
		result.s.high = input.s.high >> b;
		result.s.low = (input.s.high << (bits_in_dword - b)) | (input.s.low >> b);
	}
	return result.all;
}

int strcmp(const char *a, const char *b)
{
	return fs_strcmp(a, b);
}

int strncmp(const char *a, const char *b, size_t n)
{
	return fs_strncmp(a, b, n);
}

char *strrchr(const char *str, int character)
{
	return (char *)fs_strrchr(str, character);
}

char *strerror(int error)
{
	return (char *)fs_strerror(-error);
}

char * __strncpy_chk(char * s1, const char * s2, size_t n, size_t s1len)
{
	if (s1len < n) {
		abort();
	}
	size_t size = fs_strlen(s2);
	if (size < n) {
		fs_memcpy(s1, s2, size);
		fs_memset(s1 + size, '\0', n - size);
	} else {
		fs_memcpy(s1, s2, n);
	}
	return s1;
}

#endif
