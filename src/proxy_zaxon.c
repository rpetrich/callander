#define _GNU_SOURCE
#include "proxy.h"

#include "axon_shared.h"
#include "vfs.h"
#include "vfs_zip.h"
#include "axon.h"
#include "resolver.h"
#include "shared_mutex.h"

#include <stdatomic.h>

typedef void* mspace;
mspace create_mspace_with_base(void* base, size_t capacity, int locked);
size_t destroy_mspace(mspace msp);
void* mspace_malloc(mspace msp, size_t bytes);
void mspace_free(mspace msp, void* mem);
void* mspace_realloc(mspace msp, void* mem, size_t newsize);
void* mspace_calloc(mspace msp, size_t n_elements, size_t elem_size);
int mspace_trim(mspace msp, size_t pad);
size_t mspace_footprint(mspace msp);

static struct proxy_shared_page {
	_Alignas(PAGE_SIZE) struct resolver_config_cache resolver_config_cache;
	struct fd_global_state fd_state;
	struct vfs_zip_state zip;
	mspace space;
	struct shared_mutex alloc_lock;
	_Alignas(PAGE_SIZE) char malloc_buf[1024*1024*1024];
} shared;

intptr_t proxy_call(int syscall, proxy_arg args[PROXY_ARGUMENT_COUNT])
{
	(void)syscall;
	(void)args;
	DIE("cannot make proxy calls");
	return -ENOSYS;
}

static void *check_shared_alloc(void *ptr)
{
	if (UNLIKELY((char *)ptr < &shared.malloc_buf[0] || (char *)ptr >= &shared.malloc_buf[sizeof(shared.malloc_buf)])) {
#if 0
		DIE("shared zip heap exhausted");
#endif
		shared_mutex_lock(&shared.alloc_lock);
		mspace_free(shared.space, ptr);
		shared_mutex_unlock(&shared.alloc_lock);
		return NULL;
	}
	return ptr;
}

__attribute__((noinline))
void *shared_malloc(size_t size)
{
	shared_mutex_lock(&shared.alloc_lock);
	void *result = mspace_malloc(shared.space, size);
	shared_mutex_unlock(&shared.alloc_lock);
	return check_shared_alloc(result);
}

__attribute__((noinline))
void shared_free(void *ptr)
{
	if (ptr == NULL) {
		return;
	}
	shared_mutex_lock(&shared.alloc_lock);
	mspace_free(shared.space, ptr);
	shared_mutex_unlock(&shared.alloc_lock);
}

__attribute__((noinline))
void *shared_realloc(void *ptr, size_t size)
{
	shared_mutex_lock(&shared.alloc_lock);
	void *result = mspace_realloc(shared.space, ptr, size);
	shared_mutex_unlock(&shared.alloc_lock);
	return check_shared_alloc(result);
}

void *shared_calloc(size_t count, size_t size)
{
	shared_mutex_lock(&shared.alloc_lock);
	void *result = mspace_calloc(shared.space, count, size);
	shared_mutex_unlock(&shared.alloc_lock);
	return check_shared_alloc(result);
}

off_t shared_get_pointer_file_offset(void *ptr)
{
	return ptr - (void *)&shared;
}

struct vfs_zip_state *get_zip_state(void)
{
	return &shared.zip;
}

__attribute__((warn_unused_result)) intptr_t proxy_peek(intptr_t addr, size_t size, void *out_buffer)
{
	fs_memcpy(out_buffer, (void *)addr, size);
	return 0;
}

__attribute__((warn_unused_result)) intptr_t proxy_poke(intptr_t addr, size_t size, const void *buffer)
{
	fs_memcpy((void *)addr, buffer, size);
	return 0;
}

intptr_t proxy_alloc(size_t size)
{
	return (intptr_t)malloc(size);
}

void proxy_free(intptr_t addr, size_t size)
{
	(void)size;
	free((void *)addr);
}

#ifdef PROXY_SUPPORT_ALL_PLATFORMS
enum target_platform proxy_get_target_platform(void)
{
	return TARGET_PLATFORM_LINUX;
}
#endif

const struct vfs_path_ops *proxy_get_path_ops(void)
{
	return &zip_path_ops;
}

struct fd_global_state *get_fd_global_state(void)
{
	return &shared.fd_state;
}

struct resolver_config_cache *get_resolver_config_cache(void)
{
	return &shared.resolver_config_cache;
}

void install_proxy(const struct binary_info *self, const char **envp, bool intercept)
{
	const char *path = "callander_fixtures.zip";
	for (; *envp != NULL; ++envp) {
		if (fs_strncmp(*envp, "ZAXON_FILE=", sizeof("ZAXON_FILE=")-1) == 0) {
			const char *new_path = &(*envp)[sizeof("ZAXON_FILE=")-1];
			if (*new_path != '\0') {
				path = new_path;
			}
		}
	}

	intptr_t fd = fs_open(path, O_RDONLY, 0);
	if (fd < 0) {
		DIE("could not open archive: ", as_errno(fd));
	}

	if (fd != PROXY_FD) {
		intptr_t result = fs_dup2(fd, PROXY_FD);
		if (result < 0) {
			DIE("error duping: ", as_errno(result));
		}

		fs_close(fd);
	}

	create_shared(sizeof(shared));
	map_shared(&shared, sizeof(shared));

	shared.space = create_mspace_with_base(&shared.malloc_buf, sizeof(shared.malloc_buf), 0);
	vfs_zip_install(self->base + ((self->size + PAGE_SIZE - 1) & -PAGE_SIZE));

	if (intercept) {
		// Initialize the fd table
		initialize_fd_table();
	}
}

void configure_proxy(void)
{
	map_shared(&shared, sizeof(shared));
	vfs_zip_configure();
}
