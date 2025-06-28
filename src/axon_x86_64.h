#include <asm/prctl.h>
#include <signal.h>
#define CURRENT_AUDIT_ARCH AUDIT_ARCH_X86_64
#define CURRENT_ELF_MACHINE EM_X86_64
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define PAGE_SHIFT 12
#define ELF_ET_DYN_BASE (((1UL << 47) - PAGE_SIZE) / 3 * 2)
#define ELF_REL_RELATIVE R_X86_64_RELATIVE
#define DEFAULT_LOAD_ADDRESS 0x200000ul
#define REG_SYSCALL gregs[REG_RAX]
#define REG_ARG1 gregs[REG_RDI]
#define REG_ARG2 gregs[REG_RSI]
#define REG_ARG3 gregs[REG_RDX]
#define REG_ARG4 gregs[REG_R10]
#define REG_ARG5 gregs[REG_R8]
#define REG_ARG6 gregs[REG_R9]
#define REG_RESULT gregs[REG_RAX]
#define REG_PC gregs[REG_RIP]
#define REG_SP gregs[REG_RSP]
#define REG_BP gregs[REG_RBP]

#define USER_REG_SYSCALL rax
#define USER_REG_ARG1 rdi
#define USER_REG_ARG2 rsi
#define USER_REG_ARG3 rdx
#define USER_REG_ARG4 r10
#define USER_REG_ARG5 r8
#define USER_REG_ARG6 r9
#define USER_REG_RESULT rax
#define USER_REG_PC rip
#define USER_REG_SP rsp

#define STACK_DESCENDS

#define JUMP(pc, sp, arg0, arg1, arg2)                                                                                                                                                              \
	do {                                                                                                                                                                                            \
		__asm__ __volatile__("mov %1,%%rsp; xor %%rbp,%%rbp; xor %1,%1; push %0; xor %0,%0; ret" : : "r"(pc), "r"(sp), "D"(arg0), "S"(arg1), "d"(arg2), "a"(0), "b"(0), "c"(0), "A"(0) : "memory"); \
		__builtin_unreachable();                                                                                                                                                                    \
	} while (0)

#define AXON_RESTORE_ASM                            \
	__asm__(                                        \
		".text\n" FS_HIDDEN_FUNCTION_ASM(__restore) \
			"\n"                                    \
			"	mov $15, %rax\n");
#define AXON_ENTRYPOINT_TRAMPOLINE_ASM(name, dest) \
	__asm__(".text\n" FS_HIDDEN_FUNCTION_ASM(      \
		name) "\n"                                 \
	          ".cfi_startproc\n"                   \
	          "	xor %rbp,%rbp\n"                   \
	          "	mov %rsp,%rdi\n"                   \
	          ".weak _DYNAMIC\n"                   \
	          ".hidden _DYNAMIC\n"                 \
	          "	lea _DYNAMIC(%rip),%rsi\n"         \
	          "   subq $8,%rsp\n"                  \
	          "	jmp " #dest                        \
	          "\n"                                 \
	          ".cfi_endproc\n");

#define NAKED_FUNCTION __attribute__((naked))

__attribute__((warn_unused_result)) static inline const void *read_thread_register(void)
{
	void *result;
	__asm__ __volatile__("mov %%fs:0, %0" : "=r"(result));
	return result;
}

static inline void set_thread_register(const void *value)
{
	FS_SYSCALL(__NR_arch_prctl, ARCH_SET_FS, (intptr_t)value);
}

#define CALL_SPILLED_WITH_ARGS_AND_SP(func, arg1, arg2)                                                                                                                                                                 \
	do {                                                                                                                                                                                                                \
		register __typeof__(arg1) reg1 asm("rdi");                                                                                                                                                                      \
		reg1 = arg1;                                                                                                                                                                                                    \
		register __typeof__(arg2) reg2 asm("rsi");                                                                                                                                                                      \
		reg2 = arg2;                                                                                                                                                                                                    \
		__asm__ __volatile__("mov %%rsp,%%rdx; call " #func : "=r"(reg1), "=r"(reg2) : "r"(reg1), "r"(reg2) : "cc", "memory", "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rbp"); \
	} while (0)

#define CALL_ON_ALTERNATE_STACK_WITH_ARG(func, arg1, arg2, arg3, stack)                                                       \
	do {                                                                                                                      \
		register __typeof__(arg1) reg1 asm("rdi");                                                                            \
		reg1 = arg1;                                                                                                          \
		register __typeof__(arg2) reg2 asm("rsi");                                                                            \
		reg2 = arg2;                                                                                                          \
		register __typeof__(arg3) reg3 asm("rdx");                                                                            \
		reg3 = arg3;                                                                                                          \
		register __typeof__(stack) reg_stack asm("rcx");                                                                      \
		reg_stack = stack;                                                                                                    \
		__asm__ __volatile__("mov %%rsp,%%rbp; .cfi_def_cfa_register %%rbp; mov %%rcx,%%rsp; call " #func "; mov %%rbp,%%rsp" \
		                     : "=r"(reg1)                                                                                     \
		                     : "r"(reg1), "r"(reg2), "r"(reg3), "r"(reg_stack)                                                \
		                     : "cc", "memory", "rax", "r8", "r9", "r10", "r11", "rbp");                                       \
	} while (0)
