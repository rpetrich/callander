#ifndef PATCH_AARCH64_H
#define PATCH_AARCH64_H

#include "patch.h"

#define PATCH_SUPPORTED

void patch_body(struct thread_storage *thread, struct patch_body_args *args);

#ifdef PATCH_EXPOSE_INTERNALS

#define PCREL_JUMP_SIZE 4

#define PATCH_INCLUDES_DATA

#endif

#endif
