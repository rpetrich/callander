#define _GNU_SOURCE
#include "freestanding.h"

#include "axon.h"
AXON_BOOTSTRAP_ASM

#include <errno.h>
#include <linux/binfmts.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/prctl.h>

#include "exec.h"
#include "loader.h"
#include "proxy.h"
#include "search.h"
#include "thread_func.h"
#include "time.h"

static inline size_t ceil_to_page(size_t size)
{
	return (size + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);
}

static inline void remote_munmap(intptr_t addr, size_t length)
{
	PROXY_SEND(__NR_munmap | PROXY_NO_RESPONSE | PROXY_NO_WORKER, proxy_value(addr), proxy_value(length));
}

__attribute__((warn_unused_result))
static inline intptr_t remote_mmap(intptr_t addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	// pass through anonymous memory mapping calls
	if ((flags & MAP_ANONYMOUS) || (fd == -1)) {
		return PROXY_CALL(__NR_mmap | PROXY_NO_WORKER, proxy_value(addr), proxy_value(length), proxy_value(prot), proxy_value(flags), proxy_value(fd), proxy_value(offset));
	}
#if 0
	char path_buf[PATH_MAX];
	int link_result = fs_readlink_fd(fd, path_buf, sizeof(path_buf));
	if (link_result < 0) {
		ERROR("readlink failed", fs_strerror(link_result));
		return link_result;
	}
	path_buf[link_result] = '\0';
	int remote_fd = PROXY_CALL(__NR_open, proxy_string(path_buf), proxy_value(O_RDONLY), proxy_value(0));
	if (remote_fd < 0) {
		ERROR("reopen failed", fs_strerror(remote_fd));
		return remote_fd;
	}
	intptr_t result = PROXY_CALL(__NR_mmap | PROXY_NO_WORKER, proxy_value(addr), proxy_value(length), proxy_value(prot), proxy_value(flags), proxy_value(remote_fd), proxy_value(offset));
	PROXY_SEND(__NR_close | PROXY_NO_RESPONSE, proxy_value(remote_fd));
#else
	// block shared mappings
	if ((flags & (MAP_SHARED | MAP_PRIVATE | MAP_SHARED_VALIDATE)) != MAP_PRIVATE) {
		return -EACCES;
	}
	// setup an anonymous mapping to write into
	addr = PROXY_CALL(__NR_mmap | PROXY_NO_WORKER, proxy_value(addr), proxy_value(length), proxy_value(PROT_READ | PROT_WRITE), proxy_value(MAP_PRIVATE | MAP_ANONYMOUS | (flags & ~(MAP_SHARED | MAP_SHARED_VALIDATE))), proxy_value(-1), proxy_value(0));
	if (fs_is_map_failed((void *)addr)) {
		return addr;
	}
#if 0
	// read bytes that would be mapped and poke into the mapping
	char buf[1024 * 1024];
	size_t cur = 0;
	do {
		size_t remaining = length - cur;
		int result = fs_pread(fd, buf, remaining > sizeof(buf) ? sizeof(buf) : remaining, offset + cur);
		if (result <= 0) {
			if (result == 0) {
				break;
			}
			// unmap since we failed to read
			remote_munmap(addr, length);
			return result;
		}
		proxy_poke(addr + cur, result, buf);
		cur += result;
	} while(cur != length);
#else
	void *buf = fs_mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, offset);
	if (fs_is_map_failed(buf)) {
		remote_munmap(addr, length);
		return (intptr_t)buf;
	}
	proxy_poke(addr, length, buf);
	fs_munmap(buf, length);
#endif
	// set the memory protection as requested, if different
	if (prot != (PROT_READ | PROT_WRITE)) {
		int protect_result = PROXY_CALL(__NR_mprotect | PROXY_NO_WORKER, proxy_value(addr), proxy_value(length), proxy_value(prot));
		if (protect_result < 0) {
			// unmap since the requested protection was invalid
			remote_munmap(addr, length);
			return protect_result;
		}
	}
#endif
	return addr;
}

static uintptr_t base_address;

static int find_texec_section(const char *name, void **out_address, size_t *out_size)
{
	int self_fd = fs_open("/proc/self/exe", O_RDONLY, 0);
	if (self_fd < 0) {
		ERROR("could not open self");
		return self_fd;
	}
	struct fs_stat stat;
	int result = fs_fstat(self_fd, &stat);
	if (result < 0) {
		ERROR("could not stat self");
		fs_close(self_fd);
		return result;
	}
	void *mapped = fs_mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, self_fd, 0);
	fs_close(self_fd);
	if (fs_is_map_failed(mapped)) {
		ERROR("could not map self");
		return (intptr_t)mapped;
	}
	const ElfW(Ehdr) *header = mapped;
	const ElfW(Shdr) *strtabsh = (const ElfW(Shdr) *)((char *)mapped + header->e_shoff + header->e_shentsize * header->e_shstrndx);
	const char *strtab = (const char *)(base_address + strtabsh->sh_offset);
	for (int i = 0; i < header->e_shnum; i++) {
		const ElfW(Shdr) *sh = (const ElfW(Shdr) *)((char *)mapped + header->e_shoff + header->e_shentsize * i);
		if (fs_strcmp(&strtab[sh->sh_name], name) == 0) {
			if (sh->sh_addr != 0) {
				*out_address = (void *)(base_address + sh->sh_addr);
				*out_size = sh->sh_size;
				fs_munmap(mapped, stat.st_size);
				return 0;
			}
			ERROR("not mapped");
			return -ENOEXEC;
		}
	}
	fs_munmap(mapped, stat.st_size);
	ERROR("section not found");
	return -ENOEXEC;
}

static int map_thread_func(intptr_t *out_thread_func_addr, size_t *out_size) {
	void *thread_func;
	size_t size;
	int result = find_texec_section(THREAD_FUNC_SECTION, &thread_func, &size);
	if (result < 0) {
		return result;
	}
	size_t page_size = ceil_to_page(size);
	intptr_t thread_func_addr = remote_mmap(0, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (fs_is_map_failed((void *)thread_func_addr)) {
		ERROR("creating thread_func failed", fs_strerror(thread_func_addr));
		return (int)thread_func_addr;
	}
	proxy_poke(thread_func_addr, size, thread_func);
	int protect_result = PROXY_CALL(__NR_mprotect | PROXY_NO_WORKER, proxy_value(thread_func_addr), proxy_value(page_size), proxy_value(PROT_READ | PROT_EXEC));
	if (protect_result < 0) {
		// unmap since the requested protection was invalid
		remote_munmap(thread_func_addr, page_size);
		return protect_result;
	}
	*out_thread_func_addr = thread_func_addr;
	*out_size = size;
	return 0;
}

static int remote_load_binary(int fd, struct binary_info *out_info)
{
	const ElfW(Ehdr) header;
	int read_bytes;
	do {
		read_bytes = fs_pread(fd, (char *)&header, sizeof(header), 0);
	} while(read_bytes == -EINTR);
	if (read_bytes < 0) {
		ERROR("unable to read ELF header", fs_strerror(read_bytes));
		return -ENOEXEC;
	}
	if (read_bytes < (int)sizeof(ElfW(Ehdr))) {
		ERROR("too few bytes for ELF header", read_bytes);
		return -ENOEXEC;
	}
	// WRITE_LITERAL(TELEMETRY_FD, "Read ELF header: ");
	// write_int(TELEMETRY_FD, read_bytes);
	// WRITE_LITERAL(TELEMETRY_FD, "\n");
	if (header.e_ident[EI_MAG0] != ELFMAG0 || header.e_ident[EI_MAG1] != ELFMAG1 || header.e_ident[EI_MAG2] != ELFMAG2 || header.e_ident[EI_MAG3] != ELFMAG3) {
		ERROR("not an ELF binary");
		return -ENOEXEC;
	}
	if (header.e_ident[EI_CLASS] != CURRENT_CLASS) {
#ifdef __LP64__
		ERROR("ELF binary is not 64-bit");
#else
		ERROR("ELF binary is not 32-bit");
#endif
		return -ENOEXEC;
	}
	if (header.e_ident[EI_DATA] != ELFDATA2LSB) {
		ERROR("ELF binary is not little-endian");
		return -ENOEXEC;
	}
	if (header.e_ident[EI_VERSION] != EV_CURRENT) {
		ERROR("ELF identifier version is not current");
		return -ENOEXEC;
	}
	if (header.e_ident[EI_OSABI] != ELFOSABI_SYSV && header.e_ident[EI_OSABI] != ELFOSABI_LINUX) {
		ERROR("ELF binary ABI is not SYSV or Linux");
		return -ENOEXEC;
	}
	if (header.e_ident[EI_ABIVERSION] != 0) {
		ERROR("ELF binary has an unknown ABI version");
		return -ENOEXEC;
	}
	if (header.e_type != ET_EXEC && header.e_type != ET_DYN) {
		ERROR("ELF binary has unexpected type", (int)header.e_type);
		return -ENOEXEC;
	}
	if (header.e_machine != CURRENT_ELF_MACHINE) {
		ERROR("ELF binary has unexpected machine type", (int)header.e_machine);
		return -ENOEXEC;
	}
	if (header.e_version != EV_CURRENT) {
		ERROR("ELF binary version is not current", header.e_version);
		return -ENOEXEC;
	}
	size_t phsize = header.e_phentsize * header.e_phnum;
	out_info->header_entry_size = header.e_phentsize;
	out_info->header_entry_count = header.e_phnum;
	char phbuffer[phsize];
	int l;
	do {
		l = fs_pread(fd, phbuffer, phsize, header.e_phoff);
	} while (l == -EINTR);
	if (l != (int)phsize) {
		if (l < 0) {
			ERROR("unable to read phbuffer", fs_strerror(l));
		} else {
			ERROR("read of phbuffer was the wrong size", l);
		}
		return -ENOEXEC;
	}
	uintptr_t start = UINTPTR_MAX;
	uintptr_t off_start = 0;
	uintptr_t end = 0;
	uintptr_t off_interpreter = 0;
	const ElfW(Phdr) *dynamic_ph = NULL;
	for (int i = 0; i < header.e_phnum; i++) {
		const ElfW(Phdr) *ph = (const ElfW(Phdr) *)&phbuffer[header.e_phentsize * i];
		switch (ph->p_type) {
			case PT_LOAD: {
				if ((uintptr_t)ph->p_vaddr <= start) {
					start = (uintptr_t)ph->p_vaddr;
					off_start = (uintptr_t)ph->p_offset;
				}
				if ((uintptr_t)ph->p_vaddr + (uintptr_t)ph->p_memsz > end) {
					end = (uintptr_t)ph->p_vaddr + (uintptr_t)ph->p_memsz;
				}
				break;
			}
			case PT_DYNAMIC: {
				// WRITE_LITERAL(TELEMETRY_FD, "Found dynamic header\n");
				dynamic_ph = ph;
				break;
			}
			case PT_INTERP: {
				// WRITE_LITERAL(TELEMETRY_FD, "Found interpreter header, unsupported!\n");
				off_interpreter = ph->p_offset;
				break;
			}
			case PT_GNU_STACK: {
				// WRITE_LITERAL(TELEMETRY_FD, "Found stack header\n");
				out_info->executable_stack = ph->p_flags & PF_X ? EXECUTABLE_STACK_REQUIRED : EXECUTABLE_STACK_PROHIBITED;
				break;
			}
		}
	}
	end += PAGE_SIZE-1;
	end &= -PAGE_SIZE;
	off_start &= -PAGE_SIZE;
	start &= -PAGE_SIZE;
	size_t total_size = end - start + off_start;
	uintptr_t desired_address = start - off_start;
	intptr_t mapped_address = remote_mmap(desired_address, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (fs_is_map_failed((void *)mapped_address)) {
		ERROR("could not map binary", fs_strerror((intptr_t)mapped_address));
		return -ENOEXEC;
	}
	if ((uintptr_t)mapped_address != desired_address && header.e_type != ET_DYN) {
		ERROR("binary is not relocable");
		remote_munmap(mapped_address, end - start + off_start);
		return -ENOEXEC;
	}
	// WRITE_LITERAL(TELEMETRY_FD, "Mapped at: ");
	// write_int(TELEMETRY_FD, mapped_address);
	// WRITE_LITERAL(TELEMETRY_FD, " : ");
	// write_int(TELEMETRY_FD, mapped_address + (end - start) + off_start);
	// WRITE_LITERAL(TELEMETRY_FD, "\n");
	uintptr_t map_offset = (uintptr_t)mapped_address - start + off_start;
	for (int i = 0; i < header.e_phnum; i++) {
		const ElfW(Phdr) *ph = (const ElfW(Phdr) *)&phbuffer[header.e_phentsize * i];
		if (ph->p_type != PT_LOAD) {
			continue;
		}
		uintptr_t this_min = ph->p_vaddr & -PAGE_SIZE;
		uintptr_t this_max = (ph->p_vaddr + ph->p_memsz + PAGE_SIZE-1) & -PAGE_SIZE;
		off_t off_start = ph->p_offset & -PAGE_SIZE;
		int protection = 0;
		if (ph->p_flags & PF_R) {
			protection |= PROT_READ;
		}
		if (ph->p_flags & PF_W) {
			protection |= PROT_WRITE;
		}
		if (ph->p_flags & PF_X) {
			protection |= PROT_EXEC;
		}
		if (this_max-this_min) {
			intptr_t section_mapping = remote_mmap(map_offset + this_min, this_max-this_min, protection, MAP_PRIVATE|MAP_FIXED, fd, off_start);
			if (fs_is_map_failed((void *)section_mapping)) {
				ERROR("failed mapping section", fs_strerror((intptr_t)section_mapping));
				return -ENOEXEC;
			}
		}
		if (ph->p_memsz > ph->p_filesz) {
			size_t brk = (size_t)map_offset+ph->p_vaddr+ph->p_filesz;
			size_t pgbrk = (brk+PAGE_SIZE-1) & -PAGE_SIZE;
			// memset((void *)brk, 0, (pgbrk-brk) & (PAGE_SIZE-1));
			if (pgbrk-(size_t)map_offset < this_max) {
				intptr_t tail_mapping = remote_mmap(pgbrk, (size_t)map_offset+this_max-pgbrk, protection, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
				if (fs_is_map_failed((void *)tail_mapping)) {
					ERROR("failed creating .bss-like PT_LOAD", fs_strerror((intptr_t)tail_mapping));
					return -ENOEXEC;
				}
			}
		}
	}

	out_info->base = (void *)mapped_address;
	out_info->default_base = (void *)(start - off_start);
	out_info->size = total_size;
	out_info->program_header = (void *)((intptr_t)mapped_address + header.e_phoff);
	out_info->entrypoint = (void *)(header.e_entry - start + (intptr_t)mapped_address);
	if (dynamic_ph) {
		out_info->dynamic = (const ElfW(Dyn) *)((intptr_t)mapped_address + dynamic_ph->p_vaddr - start);
		out_info->dynamic_size = dynamic_ph->p_memsz / sizeof(ElfW(Dyn));
		out_info->dynamic_offset = dynamic_ph->p_offset;
	} else {
		out_info->dynamic = 0;
		out_info->dynamic_size = 0;
		out_info->dynamic_offset = 0;
	}
	if (off_interpreter != 0) {
		out_info->interpreter = (const char *)((intptr_t)mapped_address + off_interpreter);
	} else {
		out_info->interpreter = NULL;
	}
	return 0;
}

static void remote_unload_binary(const struct binary_info *info)
{
	if (info->base) {
		remote_munmap((intptr_t)info->base, info->size);
	}
}

__attribute__((warn_unused_result))
static int remote_exec_fd_script(int fd, const char *named_path, const char *const *argv, const char *const *envp, const ElfW(auxv_t) *aux, const char *comm, int depth, size_t header_size, char header[header_size]);
__attribute__((warn_unused_result))
static int remote_exec_fd_elf(int fd, const char *const *argv, const char *const *envp, const ElfW(auxv_t) *aux, const char *comm, const char *exec_path);

static size_t count_args(const char *const *argv, size_t *out_total_bytes) {
	size_t argc = 0;
	if (argv) {
		while (argv[argc]) {
			if (out_total_bytes) {
				*out_total_bytes += fs_strlen(argv[argc]) + 1;
			}
			argc++;
		}
	}
	return argc;
}

int remote_exec_fd(int fd, const char *named_path, const char *const *argv, const char *const *envp, const ElfW(auxv_t) *aux, const char *comm, int depth)
{
	char header[BINPRM_BUF_SIZE + 1];
	size_t header_size = fs_pread(fd, header, BINPRM_BUF_SIZE, 0);
	if ((int)header_size < 0) {
		fs_close(fd);
		ERROR("unable to read header", fs_strerror(header_size));
		return -ENOEXEC;
	}
	if (header_size < 4) {
		fs_close(fd);
		ERROR("header too small", header_size);
		return -ENOEXEC;
	}
	if (header[0] == '#' && header[1] == '!') {
		return remote_exec_fd_script(fd, named_path, argv, envp, aux, comm, depth, header_size, header);
	}
	if (header[0] == ELFMAG0 && header[1] == ELFMAG1 && header[2] == ELFMAG2 && header[3] == ELFMAG3) {
		return remote_exec_fd_elf(fd, argv, envp, aux, comm, named_path);
	}
	fs_close(fd);
	ERROR("not magic enough");
	return -ENOEXEC;
}

#define STACK_SIZE (2 * 1024 * 1024)

// remote_exec_fd_elf executes an elf binary from an open file
static int remote_exec_fd_elf(int fd, __attribute__((unused)) const char *const *argv, __attribute__((unused)) const char *const *envp, __attribute__((unused)) const ElfW(auxv_t) *aux, __attribute__((unused)) const char *comm, __attribute__((unused)) const char *exec_path)
{
	// load the main binary
	struct binary_info main_info = { 0 };
	int result = remote_load_binary(fd, &main_info);
	if (result < 0) {
		return result;
	}
	// load the interpreter, if necessary
	struct binary_info interpreter_info = { 0 };
	if (main_info.interpreter != NULL) {
		char buf[PATH_MAX];
		size_t length = proxy_peek_string((intptr_t)main_info.interpreter, PATH_MAX, buf);
		if (length == PATH_MAX) {
			remote_unload_binary(&main_info);
			ERROR("interpreter is too long", length);
			return -ENOEXEC;
		}
		int interpreter_fd = fs_openat(AT_FDCWD, buf, O_RDONLY | O_CLOEXEC, 0);
		if (UNLIKELY(interpreter_fd < 0)) {
			remote_unload_binary(&main_info);
			ERROR("unable to open ELF interpreter", fs_strerror(interpreter_fd));
			return interpreter_fd;
		}
		struct fs_stat stat;
		result = verify_allowed_to_exec(interpreter_fd, &stat, startup_euid, startup_egid);
		if (UNLIKELY(result < 0)) {
			remote_unload_binary(&main_info);
			fs_close(interpreter_fd);
			ERROR("ELF interpreter is not executable", fs_strerror(result));
			return result;
		}
		result = remote_load_binary(interpreter_fd, &interpreter_info);
		fs_close(interpreter_fd);
		if (UNLIKELY(result != 0)) {
			remote_unload_binary(&main_info);
			DIE("unable to load ELF interpreter", fs_strerror(result));
			return result;
		}
	}
	// map in thread function
	intptr_t thread_func_addr;
	size_t thread_func_size;
	result = map_thread_func(&thread_func_addr, &thread_func_size);
	if (result < 0) {
		remote_unload_binary(&interpreter_info);
		remote_unload_binary(&main_info);
		return result;
	}
	// create thread stack
	intptr_t stack = remote_mmap(0, STACK_SIZE, PROT_READ | PROT_WRITE | (main_info.executable_stack ? PROT_EXEC : 0), MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_GROWSDOWN, -1, 0);
	if (fs_is_map_failed((void *)stack)) {
		remote_unload_binary(&interpreter_info);
		remote_unload_binary(&main_info);
		ERROR("creating stack failed", fs_strerror(stack));
		return (int)stack;
	}
	// prepare thread args and dynv
	size_t string_size = sizeof("x86_64") + 16;
	size_t argc = count_args(argv, &string_size);
	size_t envc = count_args(envp, &string_size);
	size_t header_size = sizeof(struct thread_func_args) + sizeof(argc) + (argc + 1 + envc + 1) * sizeof(const char *) + 20 * sizeof(ElfW(auxv_t));
	size_t dynv_size = ((string_size + header_size + (0xf + 8)) & ~0xf) - 8;
	intptr_t dynv_base = (stack + (STACK_SIZE - dynv_size - sizeof(uint32_t))) & ~0xf;
	char dynv_buf[dynv_size];
	int string_cur = header_size;
	size_t *argc_buf = (size_t *)&dynv_buf[0];
	*argc_buf++ = argc;
	intptr_t *argv_buf = (intptr_t *)argc_buf;
	for (size_t i = 0; i < argc; i++) {
		*argv_buf++ = dynv_base + string_cur;
		for (const char *arg = argv[i];;) {
			char c = *arg++;
			dynv_buf[string_cur++] = c;
			if (c == '\0') {
				break;
			}
		}
	}
	*argv_buf++ = 0;
	intptr_t *env_buf = argv_buf;
	for (size_t i = 0; i < envc; i++) {
		*env_buf++ = dynv_base + string_cur;
		for (const char *env = envp[i];;) {
			char c = *env++;
			dynv_buf[string_cur++] = c;
			if (c == '\0') {
				break;
			}
		}
	}
	*env_buf++ = 0;
	ElfW(auxv_t) *aux_buf = (ElfW(auxv_t) *)env_buf;
	while (aux->a_type != AT_NULL) {
		aux_buf->a_type = aux->a_type;
		switch (aux->a_type) {
			case AT_BASE:
				aux_buf->a_un.a_val = (intptr_t)(main_info.entrypoint != NULL ? interpreter_info.base : main_info.base);
				aux_buf++;
				break;
			case AT_PHDR:
				aux_buf->a_un.a_val = (intptr_t)main_info.program_header;
				aux_buf++;
				break;
			case AT_PHENT:
				aux_buf->a_un.a_val = (intptr_t)main_info.header_entry_size;
				aux_buf++;
				break;
			case AT_PHNUM:
				aux_buf->a_un.a_val = (intptr_t)main_info.header_entry_count;
				aux_buf++;
				break;
			case AT_ENTRY:
				aux_buf->a_un.a_val = (intptr_t)main_info.entrypoint;
				aux_buf++;
				break;
			case AT_EXECFN:
				aux_buf->a_un.a_val = dynv_base + string_cur;
				aux_buf++;
				break;
			case AT_CLKTCK:
			case AT_PAGESZ:
			case AT_FLAGS:
			case AT_UID:
			case AT_EUID:
			case AT_GID:
			case AT_EGID:
			case AT_SECURE:
			case AT_HWCAP:
			case AT_HWCAP2:
				aux_buf->a_un.a_val = aux->a_un.a_val;
				aux_buf++;
				break;
			case AT_PLATFORM:
				aux_buf->a_un.a_val = dynv_base + string_cur;
				aux_buf++;
				fs_memcpy(&dynv_buf[string_cur], "x86_64", sizeof("x86_64"));
				string_cur += sizeof("x86_64");
				break;
			case AT_RANDOM:
				aux_buf->a_un.a_val = dynv_base + string_cur;
				aux_buf++;
				fs_memcpy(&dynv_buf[string_cur], (const char *)aux->a_un.a_val, 16);
				string_cur += 16;
				break;
			case AT_SYSINFO_EHDR:
				// TODO: system address page
				break;
		}
		++aux;
	}
	*aux_buf++ = *aux;
	struct thread_func_args *args = (struct thread_func_args *)aux_buf;
	args->pc = main_info.interpreter != NULL ? interpreter_info.entrypoint : main_info.entrypoint;
	args->sp = dynv_base;
	args->arg1 = 0;
	args->arg2 = 0;
	args->arg3 = 0;
	proxy_poke(dynv_base, dynv_size, dynv_buf);
	intptr_t tid_ptr = stack + (STACK_SIZE - sizeof(int32_t));
	// Set comm so that pgrep, for example, will work
	if (comm != NULL) {
		int prctl_result = fs_prctl(PR_SET_NAME, (uintptr_t)comm, 0, 0, 0);
		if (prctl_result < 0) {
			remote_munmap(thread_func_addr, thread_func_size);
			remote_munmap(stack, STACK_SIZE);
			remote_unload_binary(&interpreter_info);
			remote_unload_binary(&main_info);
			ERROR("failed to set name", fs_strerror(prctl_result));
			return prctl_result;
		}
	}
	// spawn remote thread
	intptr_t clone_result = PROXY_CALL(__NR_clone | PROXY_NO_WORKER, proxy_value(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID), proxy_value(dynv_base - 0x100), proxy_value(tid_ptr), proxy_value(tid_ptr), proxy_value(dynv_base + ((intptr_t)args - (intptr_t)&dynv_buf[0])), proxy_value(thread_func_addr));
	// intptr_t clone_result = PROXY_CALL(__NR_clone | PROXY_NO_WORKER, proxy_value(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID), proxy_value(dynv_base), proxy_value(tid_ptr), proxy_value(tid_ptr), proxy_value(0), proxy_value((intptr_t)args->pc));
	if (clone_result < 0) {
		remote_munmap(thread_func_addr, thread_func_size);
		remote_munmap(stack, STACK_SIZE);
		remote_unload_binary(&interpreter_info);
		remote_unload_binary(&main_info);
		ERROR("clone_result", fs_strerror(clone_result));
		return clone_result;
	}
	// wait for remote thread
	int tid;
	do {
		PROXY_CALL(__NR_futex, proxy_value(tid_ptr), proxy_value(FUTEX_WAIT), proxy_value(clone_result));
		proxy_peek(tid_ptr, sizeof(int), &tid);
	} while (tid == clone_result);
	// cleanup
	remote_munmap(thread_func_addr, thread_func_size);
	remote_munmap(stack, STACK_SIZE);
	remote_unload_binary(&interpreter_info);
	remote_unload_binary(&main_info);
	return 0;
}

static int remote_exec_fd_script(int fd, const char *named_path, const char *const *argv, const char *const *envp, const ElfW(auxv_t) *aux, const char *comm, int depth, size_t header_size, char header[header_size])
{
	// Script binary format
	if (depth > 4) {
		fs_close(fd);
		return -ELOOP;
	}
	header[header_size] = '\0';
	// Parse #! line
	char *arg0 = &header[2];
	while (*arg0 == ' ' || *arg0 == '\t') {
		arg0++;
	}
	if (*arg0 == '\n' || *arg0 == '\0') {
		fs_close(fd);
		return -ENOEXEC;
	}
	char *arg1 = arg0;
	for (;; arg1++) {
		if (*arg1 == ' ' || *arg1 == '\0') {
			*arg1++ = '\0';
			for (char *terminator = arg1; ; ++terminator) {
				if (*terminator == '\0' || *terminator == '\n') {
					*terminator = '\0';
					break;
				}
			}
			break;
		}
		if (*arg1 == '\n' || *arg1 == '\0') {
			*arg1 = '\0';
			arg1 = NULL;
			break;
		}
	}
	char path_buf[PATH_MAX];
	if (named_path == NULL) {
		// Execed via execveat, readlink to get a path to pass to the interpreter
		int link_result = fs_readlink_fd(fd, path_buf, PATH_MAX);
		if (link_result < 0) {
			fs_close(fd);
			return link_result;
		}
		named_path = path_buf;
	}
	// Recreate arguments to pass to the interpreter script
	size_t argc = count_args(argv, NULL);
	const char *new_argv[argc + 3];
	const char **dest_argv = new_argv;
	*dest_argv++ = arg0;
	if (arg1) {
		*dest_argv++ = arg1;
	}
	*dest_argv++ = named_path;
	for (size_t i = 1; i <= argc; i++) {
		*dest_argv++ = argv[i];
	}
	// WRITE_LITERAL(TELEMETRY_FD, "Executing script ");
	// fs_write(TELEMETRY_FD, named_path, fs_strlen(named_path));
	// WRITE_LITERAL(TELEMETRY_FD, " via ");
	// fs_write(TELEMETRY_FD, arg0, fs_strlen(arg0));
	// WRITE_LITERAL(TELEMETRY_FD, "\n");
	int interpreter_fd = fs_open(arg0, O_RDONLY, 0);
	if (interpreter_fd < 0) {
		fs_close(fd);
		return interpreter_fd;
	}
	struct fs_stat interpreter_stat;
	int result = verify_allowed_to_exec(interpreter_fd, &interpreter_stat, startup_euid, startup_egid);
	if (result < 0) {
		fs_close(fd);
		fs_close(interpreter_fd);
		return result;
	}
	result = remote_exec_fd(interpreter_fd, new_argv[0], new_argv, envp, aux, comm, depth + 1);
	fs_close(fd);
	return result;
}

__attribute__((used))
noreturn void release(size_t *sp, __attribute__((unused)) size_t *dynv)
{
	const char **argv = (void *)(sp+1);
	const char **current_argv = argv;
	while (*current_argv != NULL) {
		++current_argv;
	}
	const char **envp = current_argv+1;
	// Find PATH
	const char *path = "/bin:/usr/bin";
	const char **current_envp = envp;
	while (*current_envp != NULL) {
		if (fs_strncmp(*current_envp, "PATH=", 5) == 0) {
			const char *new_path = &(*current_envp)[5];
			if (*new_path != '\0') {
				path = new_path;
			}
		}
		++current_envp;
	}
	ElfW(auxv_t) *aux = (ElfW(auxv_t) *)(current_envp + 1);
	clock_load(aux);
	ElfW(auxv_t) *current_aux = aux;
	while (current_aux->a_type != AT_NULL) {
		if (current_aux->a_type == AT_PHDR) {
			base_address = (uintptr_t)current_aux->a_un.a_val & (uintptr_t)-PAGE_SIZE;
		}
		current_aux++;
	}
	const char *executable_path = argv[1];
	if (executable_path == NULL) {
		DIE("expected a program to run");
	}
	// figure out comm
	const char *comm = executable_path;
	const char *comm_attempt = comm;
	while (*comm_attempt) {
		if (*comm_attempt == '/') {
			comm = comm_attempt + 1;
		}
		comm_attempt++;
	}
	// open the main executable
	int fd = open_executable_in_paths(executable_path, path, true, startup_euid, startup_egid);
	if (UNLIKELY(fd < 0)) {
		DIE("could not find main executable", argv[1]);
	}
	int exec_result = remote_exec_fd(fd, executable_path, &argv[1], envp, aux, comm, 0);
	if (exec_result != 0) {
		DIE("remote exec failed", fs_strerror(exec_result));
	}
	fs_exit(0);
	__builtin_unreachable();
}
