#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

static void segfault_handler(int nr, siginfo_t *info, void *void_context)
{
	fprintf(stderr, "segfaulted, as expected\n");
	_exit(0);
}

int main(int argc, const char *argv[]) {
	struct sigaction sa = { 0 };
	sa.sa_flags = SA_NODEFER;
	sa.sa_sigaction = segfault_handler;
	sigaction(SIGSEGV, &sa, NULL);
	volatile int *buf = 0;
	*buf = 1;
	fprintf(stderr, "expected a segfault, not sure what happened\n");
	return 1;
}
