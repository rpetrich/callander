#define CURRENT_AUDIT_ARCH AUDIT_ARCH_I386
#define CURRENT_ELF_MACHINE EM_386
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define ELF_ET_DYN_BASE	0x000400000UL
#define ELF_REL_RELATIVE R_386_RELATIVE
#define DEFAULT_LOAD_ADDRESS 0x08040000ul
#define REG_SYSCALL gregs[REG_EAX]
#define REG_ARG1 gregs[REG_EBX]
#define REG_ARG2 gregs[REG_ECX]
#define REG_ARG3 gregs[REG_EDX]
#define REG_ARG4 gregs[REG_ESI]
#define REG_ARG5 gregs[REG_EDI]
// i386 doesn't have an ARG6!
#define REG_RESULT gregs[REG_EAX]
#define REG_PC gregs[REG_EIP]
#define REG_SP gregs[REG_ESP]
#define REG_BP gregs[REG_EBP]

#define STACK_DESCENDS

#define JUMP(pc, sp, arg0, arg1, arg2) __asm__ __volatile__("mov %1,%%esp ; jmp *%0" : : "r"(pc), "r"(sp), "a"(0), "b"(0), "d"(0) : "memory", "cc")

#define AXON_RESTORE_ASM \
__asm__( \
".text\n" \
FS_HIDDEN_FUNCTION_ASM(__restore) "\n" \
"	movl $173, %eax\n" \
);
#define AXON_IMPULSE_ASM \
__asm__( \
".text\n" \
".weak _DYNAMIC\n" \
".hidden _DYNAMIC\n" \
FS_HIDDEN_FUNCTION_ASM(impulse) "\n" \
"	mov %esp, %eax\n" \
"	sub $0x10, %esp\n" \
"	mov %eax, 0x4(%esp)\n" \
"	xor %eax, %eax\n" \
"	jmp release\n" \
);

#define NAKED_FUNCTION __attribute__((naked))

__attribute__((warn_unused_result))
static inline const void *read_thread_register(void)
{
	void *result;
	__asm__ __volatile__("mov %%gs, %0":"=r"(result));
	return result;
}

static inline void set_thread_register(const void *value)
{
	FS_SYSCALL(__NR_arch_prctl, ARCH_SET_FS, (intptr_t)value);
}

#define CALL_SPILLED_WITH_ARGS_AND_SP(func, arg1, arg2) __asm__ __volatile__("sub $0x10, %%esp; mov %%esp, 0x8(%%esp); mov %1, 0x4(%%esp); mov %0, 0x0(%%esp); call "#func"; add $0x10, %%esp" :  "=S"(arg1), "=D"(arg2) : "S"(arg1), "D"(arg2) : "cc", "memory", "eax", "ebx", "ecx", "ebp", "edx")
