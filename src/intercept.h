#ifndef INTERCEPT_H
#define INTERCEPT_H

#include "freestanding.h"

// intercept_signals will interrupt the SIGSYS and SIGBUS signals and call the appropriate handler
__attribute__((warn_unused_result))
int intercept_signals(void);

// handle_sigaction handles an incoming sigaction syscall from the program
__attribute__((warn_unused_result))
int handle_sigaction(int signal, const struct fs_sigaction *act, struct fs_sigaction *oldact, size_t size);

// handle_raise handles an incoming signal raise for the current thread
void handle_raise(int tid, int sig);

#ifdef PATCH_HANDLES_SIGILL
#define REQUIRED_SIGNALS ((1UL << (SIGSYS - 1)) | (1UL << (SIGSEGV - 1)) | (1UL << (SIGTRAP - 1)) | (1UL << (SIGILL - 1)))
#else
#define REQUIRED_SIGNALS ((1UL << (SIGSYS - 1)) | (1UL << (SIGSEGV - 1)) | (1UL << (SIGTRAP - 1)))
#endif

#endif
