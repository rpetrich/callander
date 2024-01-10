#ifndef PATCH_X86_64_H
#define PATCH_X86_64_H

#include "patch.h"

#include <signal.h>

#define PATCH_SUPPORTED

void patch_body(struct thread_storage *thread, struct patch_body_args *args);

#define PATCH_HANDLES_SIGILL
// patch_handle_illegal_instruction handles an illegal instruction
bool patch_handle_illegal_instruction(struct thread_storage *thread, ucontext_t *context);

#ifdef PATCH_EXPOSE_INTERNALS

typedef char *(*patch_address_formatter)(const uint8_t *, void *);

#define PATCH_REQUIRES_MIGRATION

__attribute__((warn_unused_result))
__attribute__((nonnull(2, 5, 7)))
bool find_patch_target(struct instruction_range basic_block, const uint8_t *target, size_t minimum_size, size_t ideal_size, patch_address_formatter formatter, void *formatter_data, struct instruction_range *out_result);

__attribute__((warn_unused_result))
size_t migrate_instructions(uint8_t *dest, const uint8_t *src, ssize_t delta, size_t byte_count, patch_address_formatter formatter, void *formatter_data);

#define PCREL_JUMP_SIZE 5

#endif

#endif
