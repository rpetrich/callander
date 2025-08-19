#ifndef AXON_H
#define AXON_H

#include "freestanding.h"

#if defined(__x86_64__)
#include "axon_x86_64.h"
#else
#if defined(__i386__)
#include "axon_i386.h"
#else
#if defined(__aarch64__)
#include "axon_aarch64.h"
#else
#error "Unsupported architecture"
#endif
#endif
#endif

#include "loader.h"

#include <stdnoreturn.h>

#define AXON_BOOTSTRAP_ASM_NO_RELEASE \
	AXON_RESTORE_ASM                  \
	FS_DEFINE_SYSCALL                 \
	AXON_ENTRYPOINT_TRAMPOLINE_ASM(impulse, release)
#ifdef STANDALONE
#define AXON_BOOTSTRAP_ASM                                                                        \
	AXON_BOOTSTRAP_ASM_NO_RELEASE                                                                 \
	int main(int argc, char *argv[], char *envp[]);                                               \
	__attribute__((used)) noreturn void release(size_t *sp, __attribute__((unused)) size_t *dynv) \
	{                                                                                             \
		char **argv = (void *)(sp + 1);                                                           \
		char **current_argv = argv;                                                               \
		while (*current_argv != NULL) {                                                           \
			++current_argv;                                                                       \
		}                                                                                         \
		char **envp = current_argv + 1;                                                           \
		char **current_envp = envp;                                                               \
		while (*current_envp != NULL) {                                                           \
			++current_envp;                                                                       \
		}                                                                                         \
		relocate_main_from_auxv((const ElfW(auxv_t) *)(current_envp + 1));                        \
		int result = main(current_argv - argv, argv, envp);                                       \
		ERROR_FLUSH();                                                                            \
		fs_exit(result);                                                                          \
		__builtin_unreachable();                                                                  \
	}
#else
#define AXON_BOOTSTRAP_ASM \
	AXON_RESTORE_ASM       \
	FS_DEFINE_SYSCALL
#endif

// #include <stdlib.h>
extern void free(void *);
extern noreturn void abort();

#include <string.h>

#define ERRORS_ARE_BUFFERED

// SELF_FD is a reserved FD that is assigned to the axon binary. it is used
// to exec new programs and is blocked from dup/close in the seccomp policy
// 0x3ff was chosen to be just under linux's default limit for file descriptors
#define SELF_FD 0x3ff

// MAIN_FD is a reserved FD that is assigned to the main binary. it is used
// to exec new programs and to emulate /proc/self/exe
#define MAIN_FD 0x3fd

// AXON_ADDR is an environment variable containing the base address at
// which to map axon. access to trapped syscalls are only allowed from a
// specific whitelisted pc, so axon must take care to remap itself to the
// appropriate address on each exec
#define AXON_ADDR "AXON_ADDR="
// AXON_COMM is an environment variable containing the program's intended
// comm value. This is used for operator contenience so that programs show up
// nicely in top and can be killed by name
#define AXON_COMM "AXON_COMM="
// AXON_EXEC is an environment variable containing the program's intended
// exec path value. This is used for tracing the intended program path
#define AXON_EXEC "AXON_EXEC="

#ifdef ENABLE_TRACER
// AXON_TRACES is an environment variable containing the traces to intercept
// and report to standard error.
#define AXON_TRACES "AXON_TRACES="
#endif

#if 0
#define ERROR_WRITEV(fd, vec, count) ((void)(fd), (void)(vec), (void)(count), 0)
#define ERROR_WRITE(fd, bytes, len) ((void)(fd), (void)(bytes), (void)(len), 0)
#define ERROR_FLUSH() \
	do {              \
	} while (0)
#else
#ifdef ERRORS_ARE_BUFFERED
extern void error_writev(const struct iovec *vec, int count);
extern void error_write(const char *buf, size_t length);
extern void error_write_str(const char *str);
extern void error_flush(void);
#define ERROR_WRITEV error_writev
#define ERROR_WRITE error_write
#define ERROR_WRITE_STR error_write_str
#define ERROR_FLUSH error_flush
#else
#define ERROR_WRITEV(vec, count)            \
	do {                                    \
		if (fs_writev(2, vec, count) < 0) { \
			abort();                        \
			__builtin_unreachable();        \
		}                                   \
	} while (0)
#define ERROR_WRITE(buf, length)            \
	do {                                    \
		if (fs_write(2, buf, length) < 0) { \
			abort();                        \
			__builtin_unreachable();        \
		}                                   \
	} while (0)
#define ERROR_WRITE_STR(str)                        \
	do {                                            \
	    const char *tmp = str;                      \
		if (fs_write(2, tmp, fs_strlen(str)) < 0) { \
			abort();                                \
			__builtin_unreachable();                \
		}                                           \
	} while (0)
#define ERROR_FLUSH() \
	do {              \
	} while (0)
#endif
#endif

struct temp_str
{
	char *str;
};

static inline struct temp_str temp_str(char *str)
{
	return (struct temp_str){.str = str};
}

struct char_range
{
	const char *buf;
	size_t size;
};

__attribute__((always_inline)) static inline struct char_range char_range(const char *buf, size_t size)
{
	return (struct char_range){
		.buf = buf,
		.size = size,
	};
}

struct error_newline
{
};

#ifndef PRODUCT_NAME
#define PRODUCT_NAME "axon"
#endif

// UNLIKELY is a macro that hints code generation that a value is unlikely
#define UNLIKELY(val) __builtin_expect(!!(val), 0)
// LIKELY is a macro that hints code generation that a value is likely
#define LIKELY(val) __builtin_expect(!!(val), 1)
// DIE is a macro that forwards its arguments to ERROR and then exits with status code 1
#define DIE(...)                 \
	do {                         \
		ERROR(__VA_ARGS__);      \
		ERROR_FLUSH();           \
		abort();                 \
		__builtin_unreachable(); \
	} while (0)


#define FE_0(WHAT)
#define FE_1(WHAT, X) WHAT(X, 1) 
#define FE_2(WHAT, X, ...) WHAT(X, 2)FE_1(WHAT, __VA_ARGS__)
#define FE_3(WHAT, X, ...) WHAT(X, 3)FE_2(WHAT, __VA_ARGS__)
#define FE_4(WHAT, X, ...) WHAT(X, 4)FE_3(WHAT, __VA_ARGS__)
#define FE_5(WHAT, X, ...) WHAT(X, 5)FE_4(WHAT, __VA_ARGS__)
#define FE_6(WHAT, X, ...) WHAT(X, 6)FE_5(WHAT, __VA_ARGS__)
#define FE_7(WHAT, X, ...) WHAT(X, 7)FE_6(WHAT, __VA_ARGS__)
#define FE_8(WHAT, X, ...) WHAT(X, 8)FE_7(WHAT, __VA_ARGS__)
#define FE_9(WHAT, X, ...) WHAT(X, 9)FE_8(WHAT, __VA_ARGS__)
#define FE_10(WHAT, X, ...) WHAT(X, 10)FE_9(WHAT, __VA_ARGS__)
#define FE_11(WHAT, X, ...) WHAT(X, 11)FE_10(WHAT, __VA_ARGS__)

#define GET_MACRO(_0,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,NAME,...) NAME 
#define FOR_EACH(action,...) GET_MACRO(_0,__VA_ARGS__,FE_11,FE_10,FE_9,FE_8,FE_7,FE_6,FE_5,FE_4,FE_3,FE_2,FE_1,FE_0)(action,__VA_ARGS__)

#define CONCAT(a, b) CONCAT_INNER(a, b)
#define CONCAT_INNER(a, b) a##b

__attribute__((always_inline)) static inline void error_discard_iovec(void *, struct iovec *vec) {
	free(vec->iov_base);
}

__attribute__((always_inline)) static inline void error_discard_noop(const void *, struct iovec *) {
}

#define ERROR_ACCEPT_(value, n) __typeof__(value) CONCAT(_log_value_, n) = value; char CONCAT(_log_buf_, n)[_Generic((value), \
	long int: 32, \
	int: 32, \
	long unsigned: 32, \
	unsigned: 32, \
    __uint128_t: 64, \
	default: 0 \
)];

#define ERROR_GENERIC_(value, prefix) _Generic((value), \
	long int: CONCAT(prefix, int), \
	int: CONCAT(prefix, int), \
	long unsigned: CONCAT(prefix, uint), \
	unsigned: CONCAT(prefix, uint), \
    __uint128_t: CONCAT(prefix, uint128), \
	struct iovec: CONCAT(prefix, iovec), \
	struct char_range: CONCAT(prefix, char_range), \
	struct temp_str: CONCAT(prefix, temp_str), \
	const char *: CONCAT(prefix, string), \
	char *: CONCAT(prefix, string), \
	struct error_newline: CONCAT(prefix, error_newline) \
)

#define ERROR_FORMAT_(value, n) ERROR_GENERIC_(value, error_format_)(CONCAT(_log_value_, n), CONCAT(_log_buf_, n))

#define ERROR_DISCARD_(value, n) _Generic((value), \
	struct temp_str: error_discard_iovec, \
	struct char_range: error_discard_iovec, \
	default: error_discard_noop \
)(CONCAT(&_log_value_, n), _log_iovec_cur++);

#ifdef ERRORS_ARE_BUFFERED
#define ERROR_RAW_(value, n) ERROR_GENERIC_(value, error_format_and_write_)(value);
#define ERROR_RAW(...) do { \
	FOR_EACH(ERROR_RAW_, ##__VA_ARGS__) \
} while(0)
#else
#define ERROR_FORMAT_COMMA_(value, n) ERROR_FORMAT_(value, n),
#define ERROR_RAW(...) do { \
	FOR_EACH(ERROR_ACCEPT_, ##__VA_ARGS__) \
	struct iovec _log_iovec[] = { \
		FOR_EACH(ERROR_FORMAT_COMMA_, ##__VA_ARGS__) \
	}; \
	ERROR_WRITEV(_log_iovec, sizeof(_log_iovec)/sizeof(_log_iovec[0])); \
	struct iovec *_log_iovec_cur = _log_iovec; \
	FOR_EACH(ERROR_DISCARD_, ##__VA_ARGS__) \
} while(0)
#endif

#define ERROR_RAW_SINGLE_(prefix, value, ...) ERROR_GENERIC_(value, error_message_write_)(prefix, value)

// ERROR is a macro that logs a message and an optional list of arguments
#define ERROR_(skip0, skip1, skip2, skip3, skip4, skip5, skip6, skip7, skip8, skip9, actual, ...) actual
#define ERROR_NOPREFIX(str, ...) ERROR_(__VA_ARGS__, \
	ERROR_RAW(((struct iovec){ str, sizeof(str)-1 }), ##__VA_ARGS__, ((struct error_newline){})), \
	ERROR_RAW(((struct iovec){ str, sizeof(str)-1 }), ##__VA_ARGS__, ((struct error_newline){})), \
	ERROR_RAW(((struct iovec){ str, sizeof(str)-1 }), ##__VA_ARGS__, ((struct error_newline){})), \
	ERROR_RAW(((struct iovec){ str, sizeof(str)-1 }), ##__VA_ARGS__, ((struct error_newline){})), \
	ERROR_RAW(((struct iovec){ str, sizeof(str)-1 }), ##__VA_ARGS__, ((struct error_newline){})), \
	ERROR_RAW(((struct iovec){ str, sizeof(str)-1 }), ##__VA_ARGS__, ((struct error_newline){})), \
	ERROR_RAW(((struct iovec){ str, sizeof(str)-1 }), ##__VA_ARGS__, ((struct error_newline){})), \
	ERROR_RAW(((struct iovec){ str, sizeof(str)-1 }), ##__VA_ARGS__, ((struct error_newline){})), \
	ERROR_RAW(((struct iovec){ str, sizeof(str)-1 }), ##__VA_ARGS__, ((struct error_newline){})), \
	ERROR_RAW_SINGLE_(str "", ##__VA_ARGS__, ""), \
	ERROR_WRITE(str "\n", sizeof(str)) \
)
#define ERROR(str, ...) ERROR_NOPREFIX(PRODUCT_NAME ": " str, ##__VA_ARGS__)

__attribute__((always_inline))
static inline struct iovec error_format_int(intptr_t value, char *buf) {
	size_t len = fs_itoa(value, buf);
	return (struct iovec){ .iov_base = buf, .iov_len = len };
}

__attribute__((always_inline))
static inline struct iovec error_format_uint(intptr_t value, char *buf) {
	size_t len = fs_utoah(value, buf);
	return (struct iovec){ .iov_base = buf, .iov_len = len };
}

static inline struct iovec error_format_uint128(__uint128_t value, char *buf)
{
	buf[0] = '0';
	buf[1] = 'x';
	size_t i = 2;
	do {
		buf[i++] = "0123456789abcdef"[(unsigned char)value & 0xf];
		value = value >> 4;
	} while (value);
	fs_reverse(&buf[2], i - 2);
	buf[i] = '\n';
	return (struct iovec){ .iov_base = buf, .iov_len = i + 1 };
}

__attribute__((always_inline))
static inline struct iovec error_format_iovec(struct iovec value, char *) {
	return value;
}

__attribute__((always_inline))
static inline struct iovec error_format_char_range(struct char_range value, char *) {
	return (struct iovec){ .iov_base = (char *)value.buf, .iov_len = value.size };
}

__attribute__((always_inline))
static inline struct iovec error_format_temp_str(struct temp_str value, char *) {
	return (struct iovec){ .iov_base = value.str, .iov_len = fs_strlen(value.str) };
}

__attribute__((always_inline))
static inline struct iovec error_format_string(const char *value, char *) {
	return (struct iovec){ .iov_base = (char *)value, .iov_len = __builtin_constant_p(value) ? strlen(value) : fs_strlen(value) };
}

__attribute__((always_inline))
static inline struct iovec error_format_error_newline(struct error_newline, char *) {
	return (struct iovec){ .iov_base = "\n", .iov_len = 1 };
}

#define ERROR_FORMAT_AND_WRITE_DEF(name, type, attribute) \
	__attribute__((unused)) attribute \
	void CONCAT(error_format_and_write_, name)(type value) { \
		ERROR_ACCEPT_(value, n) \
		struct iovec _log_iovec = ERROR_FORMAT_(value, n); \
		ERROR_WRITE(_log_iovec.iov_base, _log_iovec.iov_len); \
		struct iovec *_log_iovec_cur = &_log_iovec; \
		ERROR_DISCARD_(value, n) \
	}

ERROR_FORMAT_AND_WRITE_DEF(int, intptr_t, __attribute__((noinline)) static)
ERROR_FORMAT_AND_WRITE_DEF(uint, uintptr_t, __attribute__((noinline)) static)
ERROR_FORMAT_AND_WRITE_DEF(uint128, __uint128_t, __attribute__((noinline)) static)
ERROR_FORMAT_AND_WRITE_DEF(iovec, struct iovec, __attribute__((always_inline)) static inline)
ERROR_FORMAT_AND_WRITE_DEF(char_range, struct char_range, __attribute__((noinline)) static)
// ERROR_FORMAT_AND_WRITE_DEF(temp_str, struct temp_str, __attribute__((noinline)) static)
// ERROR_FORMAT_AND_WRITE_DEF(string, const char *, __attribute__((noinline)) static)
ERROR_FORMAT_AND_WRITE_DEF(error_newline, struct error_newline, __attribute__((noinline)) static)

__attribute__((unused)) __attribute__((always_inline)) static inline
void error_format_and_write_temp_str(struct temp_str value) {
	ERROR_WRITE_STR(value.str);
	free(value.str);
}

__attribute__((unused)) __attribute__((always_inline)) static inline
void error_format_and_write_string(const char *value) {
	ERROR_WRITE_STR(value);
}

#define ERROR_MESSAGE_WRITE_DEF(name, type) \
	__attribute__((unused)) __attribute__((noinline)) \
	static void CONCAT(error_message_write_, name)(const char *prefix, type value) { \
		ERROR_RAW(prefix, value, (struct error_newline){}); \
	}

ERROR_MESSAGE_WRITE_DEF(int, intptr_t)
ERROR_MESSAGE_WRITE_DEF(uint, uintptr_t)
ERROR_MESSAGE_WRITE_DEF(uint128, __uint128_t)
ERROR_MESSAGE_WRITE_DEF(iovec, struct iovec)
ERROR_MESSAGE_WRITE_DEF(char_range, struct char_range)
ERROR_MESSAGE_WRITE_DEF(temp_str, struct temp_str)
ERROR_MESSAGE_WRITE_DEF(string, const char *)
ERROR_MESSAGE_WRITE_DEF(error_newline, struct error_newline)

#endif
