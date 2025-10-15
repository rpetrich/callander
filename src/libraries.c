#include "libraries.h"

#include "freestanding.h"
#include "loader.h"
#include "patch.h"
#include "proxy.h"
#include "remote.h"
#include "resolver.h"
#include "tls.h"

#include <netdb.h>
#include <string.h>

struct library_info
{
	struct library_info *next;
	unsigned long name_hash;
	struct binary_info binary;
	struct symbol_info symbols;
	bool symbols_valid;
	char use_state;
	char name[];
};

static void *(*inferior_malloc)(size_t);
static struct library_info *inferior_malloc_library;

static void (*inferior_free)(void *);
static struct library_info *inferior_free_library;

static void *inferior_getaddrinfo;
static struct library_info *inferior_getaddrinfo_library;

static int *(*inferior_errno_location)(void);
static struct library_info *inferior_errno_location_library;

static int remote_getaddrinfo(const char *node, const char *service, __attribute__((unused)) const struct addrinfo *hints, struct addrinfo **res)
{
	int result = getaddrinfo_custom(node,
	                                service,
	                                hints,
	                                (struct resolver_funcs){
										.malloc = inferior_malloc,
										.free = inferior_free,
										.openat = remote_openat,
										.read = remote_read,
										.close = remote_close,
										.socket = remote_socket,
										.recvfrom = remote_recvfrom,
										.sendto = remote_sendto,
										.config_cache = get_resolver_config_cache(),
										.errno_location = inferior_errno_location(),
									},
	                                res);
	if (result == 0) {
		for (struct addrinfo *addr = *res; addr != NULL; addr = addr->ai_next) {
			switch (addr->ai_addr->sa_family) {
				case AF_INET: {
					struct sockaddr_in6 *wrapped_addr = inferior_malloc(sizeof(struct sockaddr_in6));
					wrapped_addr->sin6_family = AF_INET6;
					wrapped_addr->sin6_port = ((struct sockaddr_in *)addr->ai_addr)->sin_port;
					wrapped_addr->sin6_flowinfo = 0;
					wrapped_addr->sin6_scope_id = 0;
					// first two bytes indicate invalid multicast address
					wrapped_addr->sin6_addr.s6_addr[0] = 0xff;
					wrapped_addr->sin6_addr.s6_addr[1] = 0xff;
					wrapped_addr->sin6_addr.s6_addr[2] = 0;
					wrapped_addr->sin6_addr.s6_addr[3] = 0;
					wrapped_addr->sin6_addr.s6_addr[4] = 0;
					wrapped_addr->sin6_addr.s6_addr[5] = 0;
					wrapped_addr->sin6_addr.s6_addr[6] = 0;
					wrapped_addr->sin6_addr.s6_addr[7] = 0;
					wrapped_addr->sin6_addr.s6_addr[8] = 0;
					wrapped_addr->sin6_addr.s6_addr[9] = 0;
					wrapped_addr->sin6_addr.s6_addr[10] = 0;
					wrapped_addr->sin6_addr.s6_addr[11] = 0;
					// low bytes indicate the IPv4 address
					fs_memcpy(&wrapped_addr->sin6_addr.s6_addr[12], &((struct sockaddr_in *)addr->ai_addr)->sin_addr, sizeof(struct in_addr));
					inferior_free(addr->ai_addr);
					addr->ai_addr = (struct sockaddr *)wrapped_addr;
					addr->ai_family = AF_INET6;
					break;
				}
				case AF_INET6:
					// ~0 scope id indicates target address
					((struct sockaddr_in6 *)addr->ai_addr)->sin6_scope_id = ~(uint32_t)0;
					break;
			}
		}
	}
	return result;
}

static intptr_t new_getaddrinfo(__attribute__((unused)) uintptr_t *arguments, __attribute__((unused)) intptr_t original)
{
	const char *node = (const char *)arguments[0];
	const char *service = (const char *)arguments[1];
	const struct addrinfo *hints = (const struct addrinfo *)arguments[2];
	struct addrinfo **res = (struct addrinfo **)arguments[3];
	size_t node_len = fs_strlen(node);
	if (node_len > 7 && fs_strcmp(&node[node_len - 7], ".target") == 0) {
		// Remap a target address
		char buf[node_len - 6];
		fs_memcpy(buf, node, node_len - 6);
		buf[node_len - 7] = '\0';
		return remote_getaddrinfo(buf, service, hints, res);
	}
	int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **res) = (void *)original;
	return orig_getaddrinfo(node, (const char *)arguments[1], (const struct addrinfo *)arguments[2], (struct addrinfo **)arguments[3]);
}

static void library_loaded(__attribute__((unused)) struct library_info *library)
{
	if (library->symbols_valid) {
		if (!inferior_malloc) {
			inferior_malloc = find_symbol(&library->binary, &library->symbols, "malloc", NULL, NULL);
			if (inferior_malloc) {
				inferior_malloc_library = library;
			}
		}
		if (!inferior_free) {
			inferior_free = find_symbol(&library->binary, &library->symbols, "free", NULL, NULL);
			if (inferior_free) {
				inferior_free_library = library;
			}
		}
		if (!inferior_getaddrinfo) {
			inferior_getaddrinfo = find_symbol(&library->binary, &library->symbols, "getaddrinfo", NULL, NULL);
			if (inferior_getaddrinfo) {
				inferior_getaddrinfo_library = library;
				struct thread_storage *thread = get_thread_storage();
				if (!patch_function(thread, inferior_getaddrinfo, new_getaddrinfo, SELF_FD)) {
					ERROR("failed to patch getaddrinfo");
				}
			}
		}
		if (!inferior_errno_location) {
			inferior_errno_location = find_symbol(&library->binary, &library->symbols, "__errno_location", NULL, NULL);
			if (inferior_errno_location) {
				inferior_errno_location_library = library;
			}
		}
	}
}

static void library_unloaded(__attribute__((unused)) struct library_info *library)
{
	if (library == inferior_malloc_library) {
		inferior_malloc = NULL;
		inferior_malloc_library = NULL;
	}
	if (library == inferior_free_library) {
		inferior_free = NULL;
		inferior_free_library = NULL;
	}
	if (library == inferior_getaddrinfo_library) {
		inferior_getaddrinfo = NULL;
		inferior_getaddrinfo_library = NULL;
	}
	if (library == inferior_errno_location_library) {
		inferior_errno_location = NULL;
		inferior_errno_location_library = NULL;
	}
}

#define LIBRARY_HASHTABLE_SIZE 16
#define LIBRARY_HASHTABLE_MASK (LIBRARY_HASHTABLE_SIZE - 1)

static struct library_info *libraries[LIBRARY_HASHTABLE_SIZE];
static char active_use_state;

static struct library_info *find_library(const char *name)
{
	unsigned long hash = elf_hash((const unsigned char *)name);
	struct library_info *library = libraries[hash & LIBRARY_HASHTABLE_MASK];
	while (library != NULL) {
		if (library->name_hash == hash && fs_strcmp(name, library->name) == 0) {
			return library;
		}
		library = library->next;
	}
	return NULL;
}

void update_libraries(struct link_map *map)
{
	char new_use_state = !active_use_state;
	active_use_state = new_use_state;
	while (map != NULL) {
		intptr_t addr = map->l_addr;
		if (addr) {
			struct library_info *library = find_library(map->l_name);
			if (library == NULL) {
				size_t name_len = fs_strlen(map->l_name);
				library = malloc(sizeof(struct library_info) + name_len + 1);
				fs_memcpy(&library->name[0], map->l_name, name_len + 1);
				load_existing(&library->binary, addr);
				int result = parse_dynamic_symbols(&library->binary, (void *)addr, &library->symbols);
				library->symbols_valid = result == 0;
				unsigned long hash = elf_hash((const unsigned char *)&library->name[0]);
				library->name_hash = hash;
				unsigned long index = hash & LIBRARY_HASHTABLE_MASK;
				library->next = libraries[index];
				libraries[index] = library;
				library_loaded(library);
			}
			library->use_state = new_use_state;
		}
		map = map->l_next;
	}
	for (int i = 0; i < LIBRARY_HASHTABLE_SIZE; i++) {
		struct library_info **current = &libraries[i];
		while (*current != NULL) {
			if ((*current)->use_state != new_use_state) {
				struct library_info *unloading = *current;
				library_unloaded(unloading);
				*current = unloading->next;
				if (unloading->symbols_valid) {
					free_symbols(&unloading->symbols);
				}
				free(unloading);
			} else {
				current = &(*current)->next;
			}
		}
	}
}
