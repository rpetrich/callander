#ifndef PATCH_X86_64_H
#define PATCH_X86_64_H

#include "patch.h"

#include <signal.h>

#define PATCH_SUPPORTED

void patch_body(struct thread_storage *thread, struct patch_body_args *args);

#define PATCH_HANDLES_SIGILL
// patch_handle_illegal_instruction handles an illegal instruction
bool patch_handle_illegal_instruction(struct thread_storage *thread, ucontext_t *context);

#endif
