#ifndef PATCH_AARCH64_H
#define PATCH_AARCH64_H

#include "patch.h"

#define PATCH_SUPPORTED

void patch_body(struct thread_storage *thread, struct patch_body_args *args);

#endif
