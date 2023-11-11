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

#include <stdnoreturn.h>
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
// exec path value. This is used for tracing the intended program path in
// telemetry
#define AXON_EXEC "AXON_EXEC="

#ifdef ENABLE_TELEMETRY
// AXON_TELE is an environment variable containing the telemetry to intercept
// and report to standard error.
#define AXON_TELE "AXON_TELE="
#endif

#if 0
// ERROR_WRITE_LITERAL is a helper that writes a literal constant string
#define ERROR_WRITE_LITERAL(fd, lit) do { } while(0)
#define ERROR_WRITEV(fd, vec, count) ((void)(fd), (void)(vec), (void)(count), 0)
#define ERROR_WRITE(fd, bytes, len) ((void)(fd), (void)(bytes), (void)(len), 0)
#define ERROR_FLUSH() do { } while(0)
#else
#ifdef ERRORS_ARE_BUFFERED
extern void error_writev(const struct iovec *vec, int count);
extern void error_write(const char *buf, size_t length);
extern void error_flush(void);
#define ERROR_WRITEV error_writev
#define ERROR_WRITE error_write
#define ERROR_FLUSH error_flush
#else
#define ERROR_WRITEV(vec, count) do { if (fs_writev(2, vec, count) < 0) { abort(); __builtin_unreachable(); } } while(0)
#define ERROR_WRITE(buf, length) do { if (fs_write(2, buf, length) < 0) { abort(); __builtin_unreachable(); } } while(0)
#define ERROR_FLUSH() do { } while(0)
#endif
// ERROR_WRITE_LITERAL is a helper that writes a literal constant string
#define ERROR_WRITE_LITERAL(lit) ERROR_WRITE(lit, sizeof(lit)-1)
#endif

// error_write_uint is a helper that writes a uintptr_t in hex notation
static inline void error_write_uint(const char *prefix, size_t prefix_len, uintptr_t value)
{
	char buf[32];
	struct iovec vec[3];
	vec[0].iov_base = (void *)prefix;
	vec[0].iov_len = prefix_len;
	vec[1].iov_base = buf;
	vec[1].iov_len = fs_utoah(value, buf);
	vec[2].iov_base = "\n";
	vec[2].iov_len = 1;
	ERROR_WRITEV(vec, 3);
}
// error_write_int is a helper that writes a uintptr_t in decimal notation
static inline void error_write_int(const char *prefix, size_t prefix_len, intptr_t value)
{
	char buf[32];
	struct iovec vec[3];
	vec[0].iov_base = (void *)prefix;
	vec[0].iov_len = prefix_len;
	vec[1].iov_base = buf;
	vec[1].iov_len = fs_itoa(value, buf);
	vec[2].iov_base = "\n";
	vec[2].iov_len = 1;
	ERROR_WRITEV(vec, 3);
}
// error_write_str is a helper that writes a null-terminated string
static inline void error_write_str(const char *prefix, size_t prefix_len, const char *value)
{
	struct iovec vec[3];
	vec[0].iov_base = (void *)prefix;
	vec[0].iov_len = prefix_len;
	vec[1].iov_base = (void *)value;
	vec[1].iov_len = fs_strlen(value);
	vec[2].iov_base = "\n";
	vec[2].iov_len = 1;
	ERROR_WRITEV(vec, 3);
}

struct temp_str {
	char *str;
};

static inline struct temp_str temp_str(char *str) {
	return (struct temp_str){ .str = str };
}

// error_write_temp_str is a helper that writes a null-terminated string and frees it
static inline void error_write_temp_str(const char *prefix, size_t prefix_len, struct temp_str value)
{
	error_write_str(prefix, prefix_len, value.str);
	free(value.str);
}

struct char_range {
	const char *buf;
	size_t size;
};

__attribute__((always_inline))
static inline struct char_range char_range(const char *buf, size_t size)
{
	return (struct char_range) {
		.buf = buf,
		.size = size,
	};
}

static inline void error_write_char_range(const char *prefix, size_t prefix_len, struct char_range value)
{
	ERROR_WRITE(prefix, prefix_len);
	char buf[811];
	size_t index = 0;
	for (size_t i = 0; i < value.size; i++) {
		buf[index++] = "0123456789abcdef"[(unsigned char)value.buf[i] >> 4];
		buf[index++] = "0123456789abcdef"[(unsigned char)value.buf[i] & 0xf];
		if ((i & 3) == 3) {
			buf[index++] = ' ';
		}
		if (index >= 810) {
			ERROR_WRITE(buf, index);
			index = 0;
		}
	}
	buf[index] = '\n';
	ERROR_WRITE(buf, index+1);
}

#ifndef PRODUCT_NAME
#define PRODUCT_NAME "axon"
#endif

#define ERROR_MESSAGE_(message) do { \
	ERROR_WRITE_LITERAL(PRODUCT_NAME ": " message "\n"); \
} while(0)
#define ERROR_MESSAGE_WITH_VALUE_(message, value) do { \
	_Generic((value), \
		long int: error_write_int, \
		int: error_write_int, \
		long unsigned: error_write_uint, \
		unsigned: error_write_uint, \
		const char *: error_write_str, \
		char *: error_write_str, \
		struct char_range: error_write_char_range, \
		struct temp_str: error_write_temp_str \
	)(PRODUCT_NAME ": " message ": ", sizeof(PRODUCT_NAME ": " message ": ")-1, value); \
} while(0)
#define ERROR_(skip0, skip1, actual, ...) actual
// ERROR is a macro that logs its arguments. it accepts either a constant or a constant and a value
#define ERROR(...) ERROR_(__VA_ARGS__, ERROR_MESSAGE_WITH_VALUE_(__VA_ARGS__), ERROR_MESSAGE_(__VA_ARGS__))

// UNLIKELY is a macro that hints code generation that a value is unlikely
#define UNLIKELY(val) __builtin_expect(!!(val), 0)
// LIKELY is a macro that hints code generation that a value is likely
#define LIKELY(val) __builtin_expect(!!(val), 1)
// DIE is a macro that forwards its arguments to ERROR and then exits with status code 1
#define DIE(...) do { ERROR(__VA_ARGS__); ERROR_FLUSH(); abort(); __builtin_unreachable(); } while(0)

#endif
