#if defined(__x86_64__)

#include "x86.h"
typedef const uint8_t *ins_ptr;
#define is_jo_ins x86_is_jo_instruction
#define is_jno_ins x86_is_jno_instruction
#define is_jb_ins x86_is_jb_instruction
#define is_jae_ins x86_is_jae_instruction
#define is_je_ins x86_is_je_instruction
#define is_jne_ins x86_is_jne_instruction
#define is_jbe_ins x86_is_jbe_instruction
#define is_ja_ins x86_is_ja_instruction
#define is_js_ins x86_is_js_instruction
#define is_jns_ins x86_is_jns_instruction
#define is_jp_ins x86_is_jp_instruction
#define is_jpo_ins x86_is_jpo_instruction
#define is_jl_ins x86_is_jl_instruction
#define is_jge_ins x86_is_jge_instruction
#define is_jng_ins x86_is_jng_instruction
#define is_jg_ins x86_is_jg_instruction

#define is_return_ins x86_is_return_instruction

#else
#if defined(__aarch64__)

#include "aarch64.h"
typedef const uint32_t *ins_ptr;
#define is_jo_ins aarch64_is_jo_instruction
#define is_jno_ins aarch64_is_jno_instruction
#define is_jb_ins aarch64_is_jb_instruction
#define is_jae_ins aarch64_is_jae_instruction
#define is_je_ins aarch64_is_je_instruction
#define is_jne_ins aarch64_is_jne_instruction
#define is_jbe_ins aarch64_is_jbe_instruction
#define is_ja_ins aarch64_is_ja_instruction
#define is_js_ins aarch64_is_js_instruction
#define is_jns_ins aarch64_is_jns_instruction
#define is_jp_ins aarch64_is_jp_instruction
#define is_jpo_ins aarch64_is_jpo_instruction
#define is_jl_ins aarch64_is_jl_instruction
#define is_jge_ins aarch64_is_jge_instruction
#define is_jng_ins aarch64_is_jng_instruction
#define is_jg_ins aarch64_is_jg_instruction

#else
#error "Unsupported architecture"
#endif
#endif
