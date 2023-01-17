#define _GNU_SOURCE

#include "intercept.h"

#include <errno.h>

int handle_sigaction(int signal, const struct fs_sigaction *act, struct fs_sigaction *oldact, size_t size)
{
	(void)signal;
	(void)act;
	(void)oldact;
	(void)size;
	return -ENOSYS;
}
