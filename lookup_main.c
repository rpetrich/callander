#include "resolver.h"

#include "axon.h"

#include "loader.h"

#ifdef STANDALONE
AXON_BOOTSTRAP_ASM
#else
__asm__(
".text\n"
".global __restore\n"
".hidden __restore\n"
".type __restore,@function\n"
"__restore:\n"
"	mov $15, %rax\n"
); \
FS_DEFINE_SYSCALL
#endif

static intptr_t my_openat(int fd, const char *path, int flags, mode_t mode)
{
	return fs_openat(fd, path, flags, mode);
}

static void my_close(int fd)
{
	(void)fs_close(fd);
}

static intptr_t my_socket(int domain, int type, int protocol)
{
	return fs_socket(domain, type, protocol);
}

static intptr_t my_recvfrom(int fd, char *buf, size_t bufsz, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	return FS_SYSCALL(__NR_recvfrom, fd, (intptr_t)buf, bufsz, flags, (intptr_t)src_addr, (intptr_t)addrlen);
}

static intptr_t my_sendto(int fd, const char *buf, size_t bufsz, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
	return FS_SYSCALL(__NR_sendto, fd, (intptr_t)buf, bufsz, flags, (intptr_t)dest_addr, (intptr_t)dest_len);
}

#pragma GCC push_options
#pragma GCC optimize ("-fomit-frame-pointer")
#ifdef STANDALONE
__attribute__((noinline))
int main(const char **argv, __attribute__((unused)) const char **envp, __attribute__((unused)) const ElfW(auxv_t) *aux)
#else
__attribute__((noinline, visibility("hidden")))
int main(__attribute__((unused)) int argc, const char **argv)
#endif
{
	struct resolver_config_cache cache = { 0 };
	for (int i = 1; argv[i] != NULL; i++) {
		struct addrinfo *results = NULL;
		int local_errno = 0;
		int result = getaddrinfo_custom(argv[i], "http", NULL, (struct resolver_funcs){
			.malloc = malloc,
			.free = free,
			.openat = my_openat,
			.read = fs_read,
			.close = my_close,
			.socket = my_socket,
			.recvfrom = my_recvfrom,
			.sendto = my_sendto,
			.config_cache = &cache,
			.errno_location = &local_errno,
		}, &results);
		switch (result) {
			case 0: {
				while (results != NULL) {
					struct addrinfo *next = results->ai_next;
					struct sockaddr_in6 *addr = (struct sockaddr_in6 *)results->ai_addr;
					char buffer[16];
					int offset = 0;
					offset += fs_utoa(addr->sin6_addr.s6_addr[12], &buffer[offset]);
					buffer[offset++] = '.';
					offset += fs_utoa(addr->sin6_addr.s6_addr[13], &buffer[offset]);
					buffer[offset++] = '.';
					offset += fs_utoa(addr->sin6_addr.s6_addr[14], &buffer[offset]);
					buffer[offset++] = '.';
					offset += fs_utoa(addr->sin6_addr.s6_addr[15], &buffer[offset]);
					ERROR("result", &buffer[0]);
					free(addr);
					free(results);
					results = next;
				}
				break;
			}
			case EAI_NONAME:
				ERROR("no results");
				break;
			case EAI_SYSTEM:
				ERROR("system failure during lookup", fs_strerror(local_errno));
				break;
			default:
				ERROR("unknown error", (uintptr_t)result);
				break;
		}
	}
	return 0;
}
#pragma GCC pop_options

#ifdef STANDALONE
__attribute__((used))
noreturn void release(size_t *sp, __attribute__((unused)) size_t *dynv)
{
	const char **argv = (void *)(sp+1);
	const char **current_argv = argv;
	while (*current_argv != NULL) {
		++current_argv;
	}
	const char **envp = current_argv+1;
	const char **current_envp = envp;
	while (*current_envp != NULL) {
		++current_envp;
	}
	ElfW(auxv_t) *aux = (ElfW(auxv_t) *)(current_envp + 1);
	ElfW(auxv_t) *current_aux = aux;
	while (current_aux->a_type != AT_NULL) {
		switch (current_aux->a_type) {
			case AT_PHDR: {
				uintptr_t base = (uintptr_t)current_aux->a_un.a_val & (uintptr_t)-PAGE_SIZE;
				struct binary_info self_info;
				load_existing(&self_info, base);
				self_info.dynamic = _DYNAMIC;
				relocate_binary(&self_info);
				break;
			}
		}
		current_aux++;
	}
	int result = main(argv, envp, aux);
	ERROR_FLUSH();
	fs_exit(result);
	__builtin_unreachable();
}
#endif
