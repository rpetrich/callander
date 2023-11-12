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

void trampoline_call_handler_start();
void trampoline_call_handler_call();
void trampoline_call_handler_end();

struct instruction_range {
	const uint8_t *start;
	const uint8_t *end;
};

typedef char *(*patch_address_formatter)(const uint8_t *, void *);

__attribute__((warn_unused_result))
__attribute__((nonnull(2, 5, 7)))
bool find_patch_target(struct instruction_range basic_block, const uint8_t *target, size_t minimum_size, size_t ideal_size, patch_address_formatter formatter, void *formatter_data, struct instruction_range *out_result);

__attribute__((warn_unused_result))
size_t migrate_instructions(uint8_t *dest, const uint8_t *src, ssize_t delta, size_t byte_count, patch_address_formatter formatter, void *formatter_data);

#define INS_JMP_32_IMM 0xe9
#define INS_MOV_RCX_64_IMM_0 0x48
#define INS_MOV_RCX_64_IMM_1 0xb9

#define PCREL_JUMP_SIZE 5

#endif

#endif
