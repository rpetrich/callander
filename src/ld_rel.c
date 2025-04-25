#define _GNU_SOURCE
#include "axon.h"

// proof of concept $ORIGIN-support for ELF interpreters via chainloading
// run ld-relify.sh on your binary

AXON_BOOTSTRAP_ASM_NO_RELEASE

__attribute__((used))
noreturn void release(size_t *sp)
{
	// Skip over arguments
	char **argv = (void *)(sp+1);
	while (*argv != NULL) {
		++argv;
	}
	// skip over environment variables
	char **envp = argv+1;
	while (*envp != NULL) {
		++envp;
	}
	// relocate self
	ElfW(auxv_t) *aux = (ElfW(auxv_t) *)(envp + 1);
	struct binary_info interpreter_info;
	if (load_interpreter_from_auxv(aux, &interpreter_info) != 0) {
		fs_exit(1);
	}
	relocate_binary(&interpreter_info);
	// find auxiliary vector entries to read and patch
	ElfW(auxv_t) *phdr = NULL;
	ElfW(auxv_t) *phent = NULL;
	ElfW(auxv_t) *phnum = NULL;
	ElfW(auxv_t) *base = NULL;
	ElfW(auxv_t) *execfn = NULL;
	for (; aux->a_type != AT_NULL; aux++) {
		switch (aux->a_type) {
			case AT_PHDR:
				phdr = aux;
				break;
			case AT_PHENT:
				phent = aux;
				break;
			case AT_PHNUM:
				phnum = aux;
				break;
			case AT_BASE:
				base = aux;
				break;
			case AT_EXECFN:
				execfn = aux;
				break;
		}
	}
	if (phdr == NULL || phent == NULL || phnum == NULL || base == NULL) {
		abort();
	}
	// load the main binary so we can find the last DT_RUNPATH tag
	struct binary_info main_info;
	load_existing(&main_info, phdr->a_un.a_val & (uintptr_t)-PAGE_SIZE);
	const ElfW(Dyn) *dynamic = main_info.dynamic;
	size_t size_dynamic = main_info.dynamic_size;
	size_t runpath = 0;
	const char *strtab = NULL;
	for (int i = 0; i < (int)size_dynamic; i++) {
		switch (dynamic[i].d_tag) {
			case DT_RUNPATH:
				runpath = dynamic[i].d_un.d_ptr;
				break;
			case DT_STRTAB:
				strtab = (const char *)apply_base_address(&main_info, dynamic[i].d_un.d_ptr);
				break;
		}
	}
	if (strtab == NULL || runpath == 0) {
		abort();
	}
	// apply the $ORIGIN tag
	const char *path = &strtab[runpath];
	char buf[PATH_MAX];
	if (fs_strncmp(path, "$ORIGIN/", sizeof("$ORIGIN/")-1) == 0) {
		const char *suffix = &path[sizeof("$ORIGIN/")-1];
		const char *execfn_str = (const char *)execfn->a_un.a_val;
		size_t execfn_len = fs_strlen(execfn_str);
		while (fs_strncmp(suffix, "../", 3) == 0) {
			suffix += 3;
			while (execfn_str[--execfn_len] != '/' && execfn_len > 0) {
			}
			if (execfn_len == 0) {
				break;
			}
		}
		fs_memcpy(buf, execfn_str, execfn_len + 1);
		fs_memcpy(&buf[execfn_len+1], suffix, fs_strlen(suffix)+1);
		path = buf;
	}
	// chainload the real interpreter
	int real_interpreter = fs_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
	if (real_interpreter < 0) {
		abort();
	}
	struct binary_info real_interpreter_info;
	int result = load_binary(real_interpreter, &real_interpreter_info, 0, false);
	if (result < 0) {
		abort();
	}
	fs_close(result);
	// patch the auxiliary vector so the interpreter can find itself
	base->a_un.a_val = (ElfW(Addr))real_interpreter_info.base;
	// jump to the real interpreter
	void *pc = real_interpreter_info.entrypoint;
	JUMP(pc, sp, 0, 0, 0);
	__builtin_unreachable();
}
