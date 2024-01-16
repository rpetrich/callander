#define CURRENT_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define CURRENT_ELF_MACHINE EM_AARCH64
// PAGE_SIZE is kernel build time configurable on ARM64... need to do something about this
#ifdef __linux__
#define PAGE_SIZE 4096
#else
#define PAGE_SIZE 16384
#endif
#define PAGE_SHIFT 12
#define ELF_ET_DYN_BASE (2 * (1UL << 48) / 3)
#define ELF_REL_RELATIVE R_AARCH64_RELATIVE
#define DEFAULT_LOAD_ADDRESS 0x200000ul
#define REG_SYSCALL regs[8]
#define REG_ARG1 regs[0]
#define REG_ARG2 regs[1]
#define REG_ARG3 regs[2]
#define REG_ARG4 regs[3]
#define REG_ARG5 regs[4]
#define REG_ARG6 regs[5]
#define REG_RESULT regs[0]
#define REG_PC pc
#define REG_SP sp
#define REG_BP sp

#define USER_REG_SYSCALL REG_SYSCALL
#define USER_REG_ARG1 REG_ARG1
#define USER_REG_ARG2 REG_ARG2
#define USER_REG_ARG3 REG_ARG3
#define USER_REG_ARG4 REG_ARG4
#define USER_REG_ARG5 REG_ARG5
#define USER_REG_ARG6 REG_ARG6
#define USER_REG_RESULT REG_RESULT
#define USER_REG_PC REG_PC
#define USER_REG_SP REG_SP

#define STACK_DESCENDS

#define JUMP(pc, sp, arg0, arg1, arg2) do { \
	register intptr_t x0 asm("x0"); \
	x0 = arg0; \
	register intptr_t x1 asm("x1"); \
	x1 = arg1; \
	register intptr_t x2 asm("x2"); \
	x2 = arg2; \
	__asm__ __volatile__( \
		"mov sp, %1\n" \
		"br %0" \
		: \
		: "r"(pc), "r"(sp), "r"(x0), "r"(x1), "r"(x2) : "memory" \
	); \
} while(0)

#define AXON_RESTORE_ASM \
__asm__( \
".text\n" \
FS_HIDDEN_FUNCTION_ASM(__restore) "\n" \
"	mov x8, #139\n" \
);
#define AXON_IMPULSE_ASM \
__asm__( \
".text\n" \
FS_HIDDEN_FUNCTION_ASM(impulse) "\n" \
"	mov x29, #0\n" \
"	mov x30, #0\n" \
"	mov x0, sp\n" \
".weak _DYNAMIC\n" \
".hidden _DYNAMIC\n" \
"	adrp x1, _DYNAMIC\n" \
"	add x1, x1, #:lo12:_DYNAMIC\n" \
"	and sp, x0, #-16\n" \
"	b release\n" \
);

#define NAKED_FUNCTION

__attribute__((warn_unused_result))
static inline const void *read_thread_register(void)
{
	void *result;
	__asm__("mrs %0,tpidr_el0":"=r"(result));
	return result;
}

static inline void set_thread_register(const void *value)
{
	__asm__("msr tpidr_el0,%0"::"r"(value));
}

#define CALL_SPILLED_WITH_ARGS_AND_SP(func, arg1, arg2) do { \
	register __typeof__(arg1) x0 asm("x0"); \
	x0 = arg1; \
	register __typeof__(arg2) x1 asm("x1"); \
	x1 = arg2; \
	__asm__ __volatile__( \
		"mov x2, sp\n" \
		"bl "FS_NAME_ASM(func) \
		: "=r"(x0), "=r"(x1) \
		: "r"(x0), "r"(x1) \
		: "cc", "memory", "x30", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29" \
	); \
} while(0)

#define CALL_ON_ALTERNATE_STACK_WITH_ARG(func, arg1, arg2, arg3, stack) do { \
	register __typeof__(arg1) reg1 asm("x0"); \
	reg1 = arg1; \
	register __typeof__(arg2) reg2 asm("x1"); \
	reg2 = arg2; \
	register __typeof__(arg3) reg3 asm("x2"); \
	reg3 = arg3; \
	register __typeof__(stack) reg_stack asm("x3"); \
	reg_stack = stack; \
	__asm__ __volatile__( \
		"mov x19, sp\n" \
		".cfi_def_cfa_register x19\n" \
		"mov sp, x3\n" \
		"bl "FS_NAME_ASM(func)"\n" \
		"mov sp, x19\n" \
		".cfi_def_cfa_register sp" \
		: "=r"(reg1) \
		: "r"(reg1), "r"(reg2), "r"(reg3), "r"(reg_stack) \
		: "cc", "memory", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x30" \
	); \
} while(0)
