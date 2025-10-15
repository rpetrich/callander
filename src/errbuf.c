#include "axon.h"

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

void error_write_str(const char *str)
{
	for (;;) {
		size_t existing_offset = atomic_load(&error_offset);
		for (size_t i = existing_offset; i < sizeof(error_buffer); i++) {
			if (*str == '\0') {
				atomic_fetch_add(&error_offset, i - existing_offset);
				return;
			}
			error_buffer[i] = *str++;
		}
		error_flush();
	}
}

void error_write_char(char c)
{
	size_t i = atomic_load(&error_offset);
	if (UNLIKELY(i == sizeof(error_buffer))) {
		char copy = c;
		error_write(&copy, 1);
	} else {
		error_buffer[i] = c;
		atomic_fetch_add(&error_offset, 1);
	}
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
				(void)fs_write(2, "failed to write errors: ", sizeof("failed to write errors: ") - 1);
				const char *errorstr = fs_strerror(result);
				fs_write(2, errorstr, fs_strlen(errorstr));
				(void)fs_write(2, "\n", 1);
			} else {
				(void)fs_write(2, "failed to write errors\n", sizeof("failed to write errors\n") - 1);
			}
			abort();
			__builtin_unreachable();
		}
	}
}

#endif
