#include "printf.h"

__attribute__((used, visibility("hidden"))) int __snprintf_chk(char *__restrict buf, size_t maxlen, int __attribute__((unused)) flags, size_t len, const char *__restrict format, ...)
{
	(void)len;
	va_list va;
	va_start(va, format);
	const int ret = vsnprintf_(buf, maxlen, format, va);
	va_end(va);
	return ret;
}

#undef snprintf

__attribute__((used, visibility("hidden"))) int snprintf(char *__restrict buf, size_t maxlen, const char *__restrict format, ...)
{
	va_list va;
	va_start(va, format);
	const int ret = vsnprintf_(buf, maxlen, format, va);
	va_end(va);
	return ret;
}
