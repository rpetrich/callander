#define _GNU_SOURCE
#define PATCH_EXPOSE_INTERNALS
#include "freestanding.h"

#include "axon.h"
AXON_BOOTSTRAP_ASM

#include <errno.h>
#include <sched.h>

#include "callander_print.h"
#include "exec.h"
#include "fd_table.h"
#include "linux.h"
#include "loader.h"
#include "proxy.h"
#include "proxy_target.h"
#include "remote_exec.h"
#include "search.h"
#include "time.h"

#define PAGE_ALIGNMENT_MASK ~((uintptr_t)PAGE_SIZE - 1)

static void set_thread_pointer(const void **thread_pointer)
{
	*thread_pointer = thread_pointer;
	set_thread_register(thread_pointer);
}

static inline size_t ceil_to_page(size_t size)
{
	return (size + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);
}

void remote_munmap(intptr_t addr, size_t length)
{
	PROXY_CALL(__NR_munmap | PROXY_NO_RESPONSE | PROXY_NO_WORKER, proxy_value(addr), proxy_value(length));
}

__attribute__((warn_unused_result))
intptr_t remote_mmap(intptr_t addr, size_t length, int prot, int flags, int fd, off_t offset)
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
	struct fs_stat stat;
	intptr_t result = fs_fstat(fd, &stat);
	if (result < 0) {
		return result;
	}
	size_t padded_length = (length + (PAGE_SIZE-1)) & PAGE_ALIGNMENT_MASK;
	void *buf = fs_mmap(NULL, padded_length, PROT_READ, MAP_PRIVATE|MAP_FILE, fd, offset);
	if (fs_is_map_failed(buf)) {
		remote_munmap(addr, length);
		return (intptr_t)buf;
	}
	result = proxy_poke(addr, length > (size_t)(stat.st_size - offset) ? (size_t)(stat.st_size - offset) : length, buf);
	if (result < 0) {
		DIE("failed writing remote mmap contents", fs_strerror(result));
	}
	fs_munmap(buf, padded_length);
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

int remote_mprotect(intptr_t addr, size_t length, int prot)
{
	return PROXY_CALL(__NR_mprotect | PROXY_NO_WORKER, proxy_value(addr), proxy_value(length), proxy_value(prot));
}

intptr_t remote_mmap_stack(size_t size, int prot)
{
	return remote_mmap(0, size, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_GROWSDOWN, -1, 0);
}

int remote_load_binary(int fd, struct binary_info *out_info)
{
	const ElfW(Ehdr) header;
	int read_bytes = fs_pread_all(fd, (char *)&header, sizeof(header), 0);
	if (read_bytes < 0) {
		ERROR("unable to read ELF header", fs_strerror(read_bytes));
		return -ENOEXEC;
	}
	if (read_bytes < (int)sizeof(ElfW(Ehdr))) {
		ERROR("too few bytes for ELF header", read_bytes);
		return -ENOEXEC;
	}
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
	int l = fs_pread_all(fd, phbuffer, phsize, header.e_phoff);
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
				dynamic_ph = ph;
				break;
			}
			case PT_INTERP: {
				off_interpreter = ph->p_offset;
				break;
			}
			case PT_GNU_STACK: {
				out_info->executable_stack = ph->p_flags & PF_X ? EXECUTABLE_STACK_REQUIRED : EXECUTABLE_STACK_PROHIBITED;
				break;
			}
		}
	}
	end += PAGE_SIZE-1;
	end &= PAGE_ALIGNMENT_MASK;
	off_start &= PAGE_ALIGNMENT_MASK;
	start &= PAGE_ALIGNMENT_MASK;
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
	uintptr_t map_offset = (uintptr_t)mapped_address - start + off_start;
	for (int i = 0; i < header.e_phnum; i++) {
		const ElfW(Phdr) *ph = (const ElfW(Phdr) *)&phbuffer[header.e_phentsize * i];
		if (ph->p_type != PT_LOAD) {
			continue;
		}
		uintptr_t this_min = ph->p_vaddr & PAGE_ALIGNMENT_MASK;
		uintptr_t this_max = (ph->p_vaddr + ph->p_memsz + PAGE_SIZE-1) & PAGE_ALIGNMENT_MASK;
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
			intptr_t section_mapping = remote_mmap(map_offset + this_min, this_max-this_min, protection, MAP_PRIVATE|MAP_FIXED, fd, ph->p_offset & PAGE_ALIGNMENT_MASK);
			if (fs_is_map_failed((void *)section_mapping)) {
				ERROR("failed mapping section", fs_strerror((intptr_t)section_mapping));
				return -ENOEXEC;
			}
		}
		if (ph->p_memsz > ph->p_filesz) {
			size_t brk = (size_t)map_offset+ph->p_vaddr+ph->p_filesz;
			size_t pgbrk = (brk+PAGE_SIZE-1) & PAGE_ALIGNMENT_MASK;
			size_t zero_count = (pgbrk-brk) & (PAGE_SIZE-1);
			char zeros[PAGE_SIZE];
			memset(zeros, '\0', zero_count);
			intptr_t result = proxy_poke(brk, zero_count, &zeros);
			if (result < 0) {
				DIE("failed to write zeros", fs_strerror(result));
			}
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

void remote_unload_binary(struct binary_info *info)
{
	if (info->base) {
		remote_munmap((intptr_t)info->base, info->size);
	}
}

bool remote_should_try_to_patch(const struct recorded_syscall *syscall)
{
	return syscall->nr != LINUX_SYS_futex && syscall->nr != LINUX_SYS_restart_syscall && syscall->nr != LINUX_SYS_clock_gettime && syscall->ins != NULL;
}

static void transfer_fd_table(uintptr_t fd_table_addr)
{
	// poke the remote file table
	const int *local_table = (const int *)FS_SYSCALL(0x666);
	for (int i = 0; i < MAX_TABLE_SIZE; i++) {
		int value = local_table[i];
		if (value != 0) {
			if (value & HAS_LOCAL_FD) {
				if (i != CWD_FD) {
					value = (i << USED_BITS) | HAS_REMOTE_FD | (value & HAS_CLOEXEC);
				} else {
					continue;
				}
			} else if (value & HAS_REMOTE_FD) {
				// TODO: dup remotely and update counts
				value = (value & ~HAS_REMOTE_FD) | HAS_LOCAL_FD;
			}
			intptr_t result = proxy_poke(fd_table_addr + sizeof(int) * i, sizeof(int), &value);
			if (result < 0) {
				DIE("failed writing fd table", fs_strerror(result));
			}
		}
	}
	// open and write current working directory
	if (local_table[CWD_FD] & HAS_LOCAL_FD) {
		int local_fd = fs_open(".", O_PATH|O_DIRECTORY, 0);
		if (local_fd < 0) {
			DIE("failed opening current working directory", fs_strerror(local_fd));
		}
		int value = (local_fd << USED_BITS) | HAS_REMOTE_FD;
		intptr_t result = proxy_poke(fd_table_addr + sizeof(int) * CWD_FD, sizeof(int), &value);
		if (result < 0) {
			DIE("failed writing current working directory", fs_strerror(result));
		}
	}
}

static bool syscall_is_allowed_from_target(int syscall)
{
	switch (syscall) {
		case __NR_fchmodat:
		case __NR_fchmod:
		case __NR_fchownat:
		case __NR_fchown:
		case __NR_sendfile:
		case __NR_shutdown:
		case __NR_getsockname:
		case __NR_getpeername:
#ifdef __NR_getdents
		case __NR_getdents:
#endif
		case __NR_fstatfs:
		case __NR_setxattr:
		case __NR_lsetxattr:
		case __NR_fsetxattr:
		case __NR_getxattr:
		case __NR_lgetxattr:
		case __NR_fgetxattr:
		case __NR_listxattr:
		case __NR_flistxattr:
		case __NR_removexattr:
		case __NR_fremovexattr:
#ifdef __NR_epoll_wait
		case __NR_epoll_wait:
#endif
		case __NR_epoll_pwait:
		case __NR_epoll_create1:
		case __NR_epoll_ctl:
		case __NR_inotify_add_watch:
		case __NR_inotify_rm_watch:
		case __NR_ppoll:
		case __NR_splice:
		case __NR_tee:
		case __NR_sync_file_range:
#ifdef __NR_utime
		case __NR_utime:
#endif
		case __NR_utimensat:
#ifdef __NR_futimesat
		case __NR_futimesat:
#endif
		case __NR_fallocate:
		case __NR_readv:
		case __NR_preadv:
		case __NR_preadv2:
		case __NR_writev:
		case __NR_pwritev:
		case __NR_pwritev2:
		case __NR_fanotify_mark:
		case __NR_syncfs:
		case __NR_copy_file_range:
		case __NR_mkdirat:
		case __NR_mknodat:
		case __NR_unlinkat:
		case __NR_renameat:
		case __NR_renameat2:
		case __NR_linkat:
		case __NR_symlinkat:
		case __NR_dup:
		case __NR_connect:
		case __NR_ioctl:
		case __NR_listen:
		case __NR_bind:
		case __NR_accept4:
		case __NR_accept:
		case __NR_move_mount:
		case __NR_fsopen:
		case __NR_fsconfig:
		case __NR_fsmount:
		case __NR_fspick:
		case __NR_openat:
		case __NR_truncate:
		case __NR_read:
		case __NR_write:
		case __NR_recvfrom:
		case __NR_sendto:
		case __NR_sendmsg:
		case __NR_recvmsg:
		case __NR_lseek:
		case __NR_fadvise64:
		case __NR_readahead:
		case __NR_pread64:
		case __NR_pwrite64:
		case __NR_flock:
		case __NR_fsync:
		case __NR_fdatasync:
		case __NR_ftruncate:
		case __NR_close:
		case __NR_fcntl:
		case __NR_fstat:
		case __NR_newfstatat:
		case __NR_faccessat:
		case __NR_readlinkat:
		case __NR_getdents64:
		case __NR_socket:
		case __NR_getsockopt:
		case __NR_setsockopt:
#ifdef __NR_poll
		case __NR_poll:
#endif
			return true;
		default:
			return false;
	}
}

static char heap[TEXEC_HEAP_SIZE];

struct worker_thread_info {
	int thread_id;
	struct worker_thread_info *next;
};

struct process_syscalls_data {
	struct thandler_info *info;
	struct remote_exec_state *remote;
	intptr_t status_code;
	bool exited;
	uint32_t stream_id;
	struct worker_thread_info *threads;
	intptr_t tid_ptr;
};

static void process_syscalls(char buf[512 * 1024], struct process_syscalls_data *data);

static void *process_syscalls_thread(struct process_syscalls_data *data)
{
	const void *thread_ptr;
	set_thread_pointer(&thread_ptr);
	char buf[512 * 1024];
	process_syscalls(buf, data);
	fs_exitthread(0);
}

static void add_gdb_attach_prefix(char **buf, pid_t pid)
{
	fs_memcpy(*buf, "sudo gdb --pid=", sizeof("sudo gdb --pid=")-1);
	*buf += sizeof("sudo gdb --pid=")-1;
	*buf += fs_itoa(pid, *buf);
}

static void add_symbol_file_arg(char **buf, const char *path, int fd, const struct binary_info *local_info, const struct binary_info *remote_info)
{
	struct section_info sections;
	intptr_t result = load_section_info(fd, local_info, &sections);
	if (result == 0) {
		const ElfW(Shdr) *text_section = find_section(local_info, &sections, ".text");
		if (text_section != NULL) {
			fs_memcpy(*buf, " --eval-command=\"add-symbol-file ", sizeof(" --eval-command=\"add-symbol-file ")-1);
			*buf += sizeof(" --eval-command=\"add-symbol-file ")-1;
			size_t path_len = fs_strlen(path);
			fs_memcpy(*buf, path, path_len);
			*buf += path_len;
			**buf = ' ';
			(*buf)++;
			*buf += fs_utoah((uintptr_t)remote_info->base + text_section->sh_addr, *buf);
			fs_memcpy(*buf, "\"", sizeof("\""));
			*buf += sizeof("\"")-1;
		}
	}
}

static bool wait_for_user_continue(void)
{
	char buf[0];
	ERROR("press enter to continue");
	ERROR_FLUSH();
	return fs_read(0, &buf[0], 1) == 1;
}

struct thandler_info {
	int fd;
	struct binary_info local_info;
	struct binary_info remote_info;
	intptr_t receive_start_addr;
	intptr_t receive_syscall_addr;
	intptr_t receive_response_addr;
	intptr_t receive_clone_addr;
	intptr_t proxy_state_addr;
	intptr_t fd_table_addr;
	char path[PATH_MAX];
};

static void free_thandler(struct thandler_info *thandler)
{
	remote_unload_binary(&thandler->remote_info);
	unload_binary(&thandler->local_info);
	fs_close(thandler->fd);
}

static int init_thandler(struct thandler_info *thandler)
{
	ssize_t count = fs_readlink("/proc/self/exe", thandler->path, PATH_MAX);
	if (count < 0) {
		return count;
	}
	while (thandler->path[count-1] != '/') {
		count--;
	}
	fs_memcpy(&thandler->path[count], "thandler", sizeof("thandler"));
	intptr_t fd = fs_open(thandler->path, O_RDONLY|O_CLOEXEC, 0);
	if (fd < 0) {
		return fd;
	}
	intptr_t result = load_binary(fd, &thandler->local_info, 0, false);
	if (result < 0) {
		fs_close(fd);
		return result;
	}
	struct symbol_info symbols;
	result = load_dynamic_symbols(fd, &thandler->local_info, &symbols);
	if (result < 0) {
		fs_close(fd);
		unload_binary(&thandler->local_info);
	}
	result = remote_load_binary(fd, &thandler->remote_info);
	if (result < 0) {
		fs_close(fd);
		unload_binary(&thandler->local_info);
		free_symbols(&symbols);
		return result;
	}
	thandler->fd = fd;
	thandler->receive_start_addr = (intptr_t)find_symbol(&thandler->remote_info, &symbols, "receive_start", NULL, NULL);
	thandler->receive_syscall_addr = (intptr_t)find_symbol(&thandler->remote_info, &symbols, "receive_syscall", NULL, NULL);
	thandler->receive_response_addr = (intptr_t)find_symbol(&thandler->remote_info, &symbols, "receive_response", NULL, NULL);
	thandler->receive_clone_addr = (intptr_t)find_symbol(&thandler->remote_info, &symbols, "receive_clone", NULL, NULL);
	thandler->proxy_state_addr = (intptr_t)find_symbol(&thandler->remote_info, &symbols, "proxy_state", NULL, NULL);
	thandler->fd_table_addr = (intptr_t)find_symbol(&thandler->remote_info, &symbols, "fd_table", NULL, NULL);
	free_symbols(&symbols);
	// relocate remotely
	uintptr_t rela = 0;
	uintptr_t relasz = 0;
	uintptr_t relaent = 0;
	const ElfW(Dyn) *dynamic = thandler->local_info.dynamic;
	size_t size_dynamic = thandler->local_info.dynamic_size;
	for (int i = 0; i < (int)size_dynamic; i++) {
		switch (dynamic[i].d_tag) {
			case DT_RELA:
				rela = dynamic[i].d_un.d_ptr;
				break;
			case DT_RELASZ:
				relasz = dynamic[i].d_un.d_val;
				break;
			case DT_RELAENT:
				relaent = dynamic[i].d_un.d_val;			
				break;
		}
	}
	uintptr_t local_base = (uintptr_t)thandler->local_info.base;
	uintptr_t remote_base = (uintptr_t)thandler->remote_info.base;
	uintptr_t rel_base = apply_base_address(&thandler->local_info, rela);
	for (uintptr_t rel_off = 0; rel_off < relasz; rel_off += relaent) {
		const ElfW(Rel) *rel = (const ElfW(Rel) *)(rel_base + rel_off);
		if (rel->r_info == ELF_REL_RELATIVE) {
			uintptr_t value = remote_base + *(uintptr_t *)(local_base + rel->r_offset);
			result = proxy_poke(remote_base + rel->r_offset, sizeof(value), &value);
			if (result < 0) {
				free_thandler(thandler);
				return result;
			}
		}
	}
	return 0;
}

static int process_syscalls_until_exit(struct remote_exec_state *remote, struct thandler_info *thandler)
{
	struct process_syscalls_data data = {0};
	data.remote = remote;
	data.info = thandler;
	data.tid_ptr = remote->stack_end - sizeof(pid_t);
	uint32_t stream_id = proxy_generate_stream_id();
	data.stream_id = stream_id;
	struct proxy_target_state new_proxy_state = { 0 };
	new_proxy_state.stream_id = stream_id;
	new_proxy_state.heap = (uintptr_t)&heap;
	new_proxy_state.target_state = proxy_get_hello_message()->state;
	intptr_t result = proxy_poke(thandler->proxy_state_addr, sizeof(new_proxy_state), &new_proxy_state);
	if (result < 0) {
		ERROR("failed target proxy state", fs_strerror(result));
		return -ENOEXEC;
	}
	// initialize the remote file descriptor table
	bool debug = remote->debug;
	if (debug) {
		ERROR("transferring file descriptor table");
		ERROR_FLUSH();
	}
	transfer_fd_table(thandler->fd_table_addr);
	// print a gdb command to attach remotely if debugging
	char buf[512 * 1024];
	if (debug) {
		char *cur_buf = &buf[0];
		add_gdb_attach_prefix(&cur_buf, PROXY_CALL(LINUX_SYS_getpid));
		add_symbol_file_arg(&cur_buf, thandler->path, thandler->fd, &thandler->local_info, &thandler->remote_info);
		// add_symbol_file_arg(&cur_buf, analysis.loader.main->loaded_path, fd, &analysis.loader.main->info, &main_info);
		// if (state.analysis->loader.interpreter) {
		// 	add_symbol_file_arg(&cur_buf, analysis.loader.main->info.interpreter, interpreter_fd, &analysis.loader.interpreter->info, &interpreter_info);
		// }
		ERROR("remote debugging command", &buf[0]);
		// wait to proceed
		if (!wait_for_user_continue()) {
			ERROR("exiting");
			ERROR_FLUSH();
			return -ENOLINK;
		}
	}
	// Set comm so that pgrep, for example, will work
#ifdef PR_SET_NAME
	if (remote->comm != NULL) {
		if (debug) {
			ERROR("updating local comm");
			ERROR_FLUSH();
		}
		intptr_t result = fs_prctl(PR_SET_NAME, (uintptr_t)remote->comm, 0, 0, 0);
		if (result < 0) {
			ERROR("failed to set comm", fs_strerror(result));
			return result;
		}
	}
#endif
	// spawn remote thread
	if (debug) {
		ERROR("spawning remote thread");
		ERROR_FLUSH();
	}
	intptr_t clone_result = PROXY_CALL(LINUX_SYS_clone | PROXY_NO_WORKER, proxy_value(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_THREAD | CLONE_SETTLS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID), proxy_value(/*dynv_base - 0x100*/0), proxy_value(data.tid_ptr), proxy_value(data.tid_ptr), proxy_value(remote->sp), proxy_value(thandler->receive_start_addr));
	if (clone_result < 0) {
		ERROR("failed to clone", fs_strerror(clone_result));
		return clone_result;
	}
	if (debug) {
		ERROR("processing syscalls");
		ERROR_FLUSH();
	}
	process_syscalls(buf, &data);
	if (debug) {
		if (data.threads) {
			ERROR("received status code, waiting for workers", data.status_code);
		} else {
			ERROR("received status code, waiting for exit", data.status_code);
		}
		ERROR_FLUSH();
	}
	// wait for workers
	for (struct worker_thread_info *worker = data.threads; worker != NULL; ) {
		for (;;) {
			int thread_id = worker->thread_id;
			if (thread_id == 0) {
				break;
			}
			(void)fs_futex(&worker->thread_id, FUTEX_WAIT, thread_id, NULL);
		}
		void *worker_stack = worker;
		worker = worker->next;
		fs_munmap(worker_stack, PROXY_WORKER_STACK_SIZE);
	}
	// wait for remote thread
	if (debug) {
		ERROR("waiting for remote thread");
		ERROR_FLUSH();
	}
	pid_t tid;
	do {
		PROXY_CALL(__NR_futex, proxy_value(data.tid_ptr), proxy_value(FUTEX_WAIT), proxy_value(clone_result));
		result = proxy_peek(data.tid_ptr, sizeof(pid_t), &tid);
		if (result < 0) {
			DIE("failed to wait for thread to exit", fs_strerror(result));
		}
	} while (tid == clone_result);
	return data.status_code;
}

static void process_syscalls(char buf[512 * 1024], struct process_syscalls_data *data)
{
	uint32_t stream_id = data->stream_id;
	intptr_t receive_response_addr = data->info->receive_response_addr;
	bool debug = data->remote->debug;
	request_message message;
	for (;;) {
		char description_buf[256];
		struct iovec vec[PROXY_ARGUMENT_COUNT];
		size_t io_count = 0;
		intptr_t result = 0;
		intptr_t result_id = proxy_read_stream_message_start(stream_id, &message, &data->exited);
		if (UNLIKELY(result_id < 0)) {
			if (result_id == -ECANCELED) {
				return;
			}
			DIE("proxy_read_stream_message_start returned unexpected error", fs_strerror(result_id));
			return;
		}
		switch (message.template.nr) {
			case TARGET_NR_PEEK: {
				if (debug) {
					ERROR("received a peek");
					ERROR_FLUSH();
				}
				proxy_read_stream_message_finish(stream_id);
				char *addr = (char *)message.values[0];
				size_t size = message.values[1];
				if (addr >= heap && addr + size < &heap[sizeof(heap)]) {
					io_count = 1;
					vec[0].iov_base = addr;
					vec[0].iov_len = size;
				} else {
					ERROR("invalid peek of", (uintptr_t)addr);
					ERROR("with size", (intptr_t)size);
					ERROR_FLUSH();
				}
				break;
			}
			case TARGET_NR_POKE | PROXY_NO_RESPONSE: {
				if (debug) {
					ERROR("received a poke");
					ERROR_FLUSH();
				}
				char *addr = (char *)message.values[0];
				size_t size = message.values[1];
				if (addr >= heap && addr + size < &heap[sizeof(heap)]) {
					size_t bytes_read = 0;
					while (size != bytes_read) {
						result = proxy_read_stream_message_body(stream_id, &addr[bytes_read], size - bytes_read);
						if (result <= 0) {
							if (result == -EINTR) {
								continue;
							}
							DIE("Failed to read from socket", fs_strerror(result));
						}
						bytes_read += result;
					}
				} else {
					ERROR("invalid poke of", (uintptr_t)addr);
					ERROR("with size", (intptr_t)size);
					ERROR_FLUSH();
				}
				proxy_read_stream_message_finish(stream_id);
				break;
			}
			case __NR_clone | PROXY_NO_RESPONSE: {
				if (debug) {
					ERROR("child spawned a thread");
					ERROR_FLUSH();
				}
				void *stack = fs_mmap(NULL, PROXY_WORKER_STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_GROWSDOWN, -1, 0);
				if (fs_is_map_failed(stack)) {
					ERROR("unable to map a worker stack", fs_strerror((intptr_t)stack));
					ERROR_FLUSH();
					break;
				}
				struct worker_thread_info *info = stack;
				info->thread_id = 0;
				info->next = data->threads;
				data->threads = info;
				result = fs_clone(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_THREAD | CLONE_SETTLS | CLONE_CHILD_CLEARTID | CLONE_PARENT_SETTID, stack + PROXY_WORKER_STACK_SIZE, &info->thread_id, &info->thread_id, data, process_syscalls_thread);
				if (result < 0) {
					fs_munmap(stack, PROXY_WORKER_STACK_SIZE);
					ERROR("unable to start a worker thread", fs_strerror(result));
					ERROR_FLUSH();
					break;
				}
				proxy_read_stream_message_finish(stream_id);
				break;
			}
			case __NR_set_tid_address | PROXY_NO_RESPONSE: {
				intptr_t value = message.values[0];
				data->tid_ptr = value;
				proxy_read_stream_message_finish(stream_id);
				if (debug) {
					ERROR("received set tid address", (uintptr_t)value);
					ERROR_FLUSH();
				}
				break;
			}
			case __NR_exit_group | PROXY_NO_RESPONSE:
				if (debug) {
					ERROR("received an exit");
					ERROR_FLUSH();
				}
				data->status_code = message.values[0];
				data->exited = true;
				proxy_read_stream_message_finish(stream_id);
				return;
			case 0x666: {
				proxy_read_stream_message_finish(stream_id);
				int fd = message.values[0];
				intptr_t len = fs_readlink_fd(fd, buf, PATH_MAX);
				if (len >= 0) {
					buf[len] = '\0';
					// ERROR("mapped", buf);
				}
				uintptr_t remote_address = message.values[1];
				// ERROR("at", remote_address);
				for (struct loaded_binary *binary = data->remote->analysis.loader.binaries; binary != NULL; binary = binary->next) {
					if (binary->child_base == 0 && fs_strcmp(binary->loaded_path, buf) == 0) {
						if (debug) {
							ERROR("known library loaded", binary->path);
							ERROR_FLUSH();
						}
						binary->child_base = remote_address;
						repatch_remote_syscalls(data->remote);
						if (debug && binary->has_sections) {
							const ElfW(Shdr) *text_section = find_section(&binary->info, &binary->sections, ".text");
							if (text_section != NULL) {
								char *cur = buf;
								fs_memcpy(cur, "add-symbol-file ", sizeof("add-symbol-file ")-1);
								cur += sizeof("add-symbol-file ")-1;
								size_t loaded_path_len = fs_strlen(binary->loaded_path);
								fs_memcpy(cur, binary->loaded_path, loaded_path_len);
								cur += loaded_path_len;
								*cur++ = ' ';
								fs_utoah(remote_address + text_section->sh_addr, cur);
								ERROR("additional debug command", buf);
								ERROR_FLUSH();
								// if (!wait_for_user_continue()) {
								// 	DIE("exiting");
								// }
							}
						}
						goto after_unknown_library_message;
					}
				}
				if (debug) {
					ERROR("unknown library loaded", buf);
					ERROR_FLUSH();
				}
			after_unknown_library_message:
				break;
			}
			default: {
				intptr_t syscall = message.template.nr & ~TARGET_NO_RESPONSE;
				if (debug) {
					const char *syscall_desc = name_for_syscall(syscall);
					size_t syscall_desc_len = fs_strlen(syscall_desc);
					fs_memcpy(description_buf, syscall_desc, syscall_desc_len);
					int offset = syscall_desc_len;
					description_buf[offset++] = '(';
					int argc = info_for_syscall(syscall).attributes & SYSCALL_ARGC_MASK;
					for (int i = 0; i < argc; i++) {
						if (i != 0) {
							description_buf[offset++] = ',';
							description_buf[offset++] = ' ';
						}
						bool is_in = message.template.is_in & (1 << i);
						bool is_out = message.template.is_out & (1 << i);
						if (is_in) {
							if (is_out) {
								fs_memcpy(&description_buf[offset], "<in-out>", sizeof("<in-out>")-1);
								offset += sizeof("<in-out>")-1;
							} else {
								fs_memcpy(&description_buf[offset], "<in>", sizeof("<in>")-1);
								offset += sizeof("<in>")-1;
							}
						} else {
							if (is_out) {
								fs_memcpy(&description_buf[offset], "<out>", sizeof("<out>")-1);
								offset += sizeof("<out>")-1;
							} else {
								if (message.values[i] == (uintptr_t)AT_FDCWD) {
									fs_memcpy(&description_buf[offset], "AT_FDCWD", sizeof("AT_FDCWD")-1);
									offset += sizeof("AT_FDCWD")-1;
								} else {
									offset += fs_utoah(message.values[i], &description_buf[offset]);
								}
							}
						}
					}
					description_buf[offset++] = ')';
					description_buf[offset++] = '\0';
					if (message.template.nr & TARGET_NO_RESPONSE) {
						ERROR("received syscall (no response)", description_buf);
					} else {
						ERROR("received syscall", description_buf);
					}
					ERROR_FLUSH();
				}
				size_t trailer_bytes = 0;
				intptr_t index = 0;
				uint64_t values[6];
				for (int i = 0; i < 6; i++) {
					if (message.template.is_in & (1 << i)) {
						trailer_bytes += message.values[i];
						if (message.template.is_out & (1 << i)) {
							vec[io_count].iov_base = &buf[index];
							vec[io_count].iov_len = message.values[i];
							io_count++;
						}
						values[i] = (intptr_t)&buf[index];
						index += message.values[i];
					} else if (message.template.is_out & (1 << i)) {
					} else {
						values[i] = message.values[i];
					}
				}
				for (int i = 0; i < 6; i++) {
					if (message.template.is_in & (1 << i)) {
						if (message.template.is_out & (1 << i)) {
						}
					} else if (message.template.is_out & (1 << i)) {
						vec[io_count].iov_base = &buf[index];
						vec[io_count].iov_len = message.values[i];
						io_count++;
						values[i] = (intptr_t)&buf[index];
						index += message.values[i];
					}
				}
				// read trailer
				// ERROR("trailer_bytes", trailer_bytes);
				// ERROR_FLUSH();
				size_t bytes_read = 0;
				while (trailer_bytes != bytes_read) {
					result = proxy_read_stream_message_body(stream_id, &buf[bytes_read], trailer_bytes - bytes_read);
					if (result <= 0) {
						if (result == -EINTR) {
							continue;
						}
						DIE("Failed to read from socket", fs_strerror(result));
					}
					bytes_read += result;
				}
				proxy_read_stream_message_finish(stream_id);
				if (syscall_is_allowed_from_target(syscall)) {
					result = FS_SYSCALL(syscall, values[0], values[1], values[2], values[3], values[4], values[5]);
				} else {
					if (debug) {
						ERROR("requested syscall is not allowed");
						ERROR_FLUSH();
					}
					result = -ENOSYS;
				}
				break;
			}
		}
		if ((message.template.nr & TARGET_NO_RESPONSE) == 0) {
			if (debug) {
				if (result < 0) {
					ERROR("=", fs_strerror(result));
				} else {
					ERROR("=", (uintptr_t)result);
				}
				ERROR_FLUSH();
			}
			proxy_arg return_args[PROXY_ARGUMENT_COUNT];
			return_args[0] = proxy_value(receive_response_addr);
			return_args[1] = proxy_value(result_id);
			return_args[2] = proxy_value(result);
			size_t i = 0;
			for (; i < io_count; i++) {
				if (i+3 >= PROXY_ARGUMENT_COUNT) {
					DIE("too many output arguments");
				}
				return_args[i+3] = proxy_in(vec[i].iov_base, vec[i].iov_len);
			}
			for (i += 3; i < PROXY_ARGUMENT_COUNT; i++) {
				return_args[i] = proxy_value(0);
			}
			proxy_call(TARGET_NR_CALL | TARGET_NO_RESPONSE, return_args);
		}
	}
}

__attribute__((used))
noreturn void release(size_t *sp, __attribute__((unused)) size_t *dynv)
{
	const char **argv = (void *)(sp+1);
	const void *thread_ptr;
	set_thread_pointer(&thread_ptr);
	bool debug = false;
	if (argv[0] != NULL && argv[1] != NULL && fs_strcmp(argv[1], "--debug") == 0) {
		debug = true;
		argv++;
	}
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
			uintptr_t base_address = (uintptr_t)current_aux->a_un.a_val & (uintptr_t)PAGE_ALIGNMENT_MASK;
			struct binary_info self_info;
			load_existing(&self_info, base_address);
			relocate_binary(&self_info);
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

	// initialize thandler running remotely
	if (debug) {
		ERROR("remotely loading call handler");
		ERROR_FLUSH();
	}
	struct thandler_info thandler;
	intptr_t result = init_thandler(&thandler);
	if (result < 0) {
		DIE("failed to load thandler", fs_strerror(result));
	}
	LOG("mapped thandler", &thandler.path[0]);
	LOG("at", (uintptr_t)thandler.remote_info.base);
	if (thandler.receive_start_addr == 0 || thandler.receive_clone_addr == 0 || thandler.receive_syscall_addr == 0 || thandler.receive_response_addr == 0 || thandler.proxy_state_addr == 0 || thandler.fd_table_addr == 0) {
		free_thandler(&thandler);
		ERROR("missing thandler symbols");
	}

	// remotely execute it
	struct remote_exec_state remote;
	result = remote_exec_fd(NULL, fd, executable_path, &argv[1], envp, aux, comm, 0, debug, (struct remote_handlers){ .receive_syscall_addr = thandler.receive_syscall_addr, .receive_clone_addr = thandler.receive_clone_addr }, &remote);
	if (result < 0) {
		DIE("remote exec failed", fs_strerror(result));
		fs_exit(-result);
	}

	// process incoming syscall requests
	result = process_syscalls_until_exit(&remote, &thandler);

	// cleanup the mess
	cleanup_remote_exec(&remote);
	free_thandler(&thandler);
	fs_exit(result);

	__builtin_unreachable();
}
