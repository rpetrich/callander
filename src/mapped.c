#include "mapped.h"

#include <errno.h>

#include "attempt.h"
#include "freestanding.h"
#include "axon.h"

#define USE_MINCORE 1

#if USE_MINCORE
#else
struct mapped_args {
	const void *address;
	size_t length;
	bool result;
};
static void region_is_mapped_body(__attribute__((unused)) struct thread_storage *thread, struct mapped_args *args) {
	intptr_t low = (intptr_t)args->address & -PAGE_SIZE;
	intptr_t high = ((intptr_t)args->address + args->length + (PAGE_SIZE - 1)) & -PAGE_SIZE;
	for (; low != high; low += PAGE_SIZE) {
		*(const volatile uint8_t*)low;
	}
	args->result = true;
}
#endif

bool region_is_mapped(__attribute__((unused)) struct thread_storage *thread, const void *address, size_t length)
{
#if USE_MINCORE
	intptr_t low = (intptr_t)address & -PAGE_SIZE;
	intptr_t high = ((intptr_t)address + length + (PAGE_SIZE - 1)) & -PAGE_SIZE;
	size_t page_delta = high - low;
	unsigned char dummy[page_delta / PAGE_SIZE];
	return fs_mincore((const void *)low, page_delta, dummy) != -ENOMEM;
#else
	struct mapped_args args = {
		.address = address,
		.length = length,
		.result = false,
	};
	attempt(thread, (attempt_body)&region_is_mapped_body, &args);
	return args.result;
#endif
}

__attribute__((warn_unused_result))
static bool read_mapping(char *buf, struct mapping *out_mapping)
{
	uintptr_t start;
	const char *dash_character = fs_scanu(buf, &start);
	if (dash_character == NULL || *dash_character != '-') {
		return false;
	}
	uintptr_t end;
	const char *space_character = fs_scanu(dash_character + 1, &end);
	if (space_character == NULL || *space_character != ' ') {
		return false;
	}
	uint8_t prot = 0;
	if (space_character[1] == 'r') {
		prot |= PROT_READ;
	}
	if (space_character[1] == '\0') {
		return false;
	}
	if (space_character[2] == 'w') {
		prot |= PROT_WRITE;
	}
	if (space_character[2] == '\0') {
		return false;
	}
	if (space_character[3] == 'x') {
		prot |= PROT_EXEC;
	}
	if (space_character[3] == '\0') {
		return false;
	}
	uint8_t flags = 0;
	if (space_character[4] == 'p') {
		flags |= MAP_PRIVATE;
	}
	if (space_character[4] == 's') {
		flags |= MAP_SHARED;
	}
	if (space_character[4] == '\0' || space_character[5] == '\0') {
		return false;
	}
	uintptr_t offset;
	const char *after_offset = fs_scanu(&space_character[6], &offset);
	if (*after_offset != ' ') {
		return false;
	}
	uintptr_t dev_major;
	const char *after_dev_major = fs_scanu(&after_offset[1], &dev_major);
	if (*after_dev_major != ':') {
		return false;
	}
	uintptr_t dev_minor;
	const char *after_dev_minor = fs_scanu(&after_dev_major[1], &dev_minor);
	if (*after_dev_minor != ' ') {
		return false;
	}
	intptr_t inode;
	const char *after_inode = fs_scans(&after_dev_minor[1], &inode);
	if (*after_inode != ' ') {
		return false;
	}
	out_mapping->start = (void *)start;
	out_mapping->end = (void *)end;
	out_mapping->offset = offset;
	out_mapping->device = (dev_major << 8) | dev_minor;
	out_mapping->inode = inode;
	out_mapping->prot = prot;
	out_mapping->flags = flags;
	out_mapping->path[0] = '\0';
	while (*after_inode == ' ') {
		after_inode++;
	}
	if (*after_inode == '\0') {
		return true;
	}
	int i = 0;
	for (; after_inode[i] && (i < PATH_MAX - 1); i++) {
		out_mapping->path[i] = after_inode[i];
	}
	out_mapping->path[i] = '\0';
	return true;
}

int lookup_mapping_for_address(const void *address, struct mapping *out_mapping)
{
	struct maps_file_state file;
	init_maps_file_state(&file);
	int fd = fs_open("/proc/self/maps", O_RDONLY, 0);
	if (fd < 0) {
		return fd;
	}
	int result;
	for (;;) {
		result = read_next_mapping_from_file(fd, &file, out_mapping);
		if (result == 1) {
			if (out_mapping->start <= address && address < out_mapping->end) {
				break;
			}
		} else {
			if (result == 0) {
				result = -EINVAL;
			}
			break;
		}
	}
	fs_close(fd);
	return result;
}

void init_maps_file_state(struct maps_file_state *out_maps_file)
{
	out_maps_file->buf_offset = 0;
	out_maps_file->count = 0;
}

__attribute__((warn_unused_result))
int read_next_mapping_from_file(int fd, struct maps_file_state *f, struct mapping *out_mapping)
{
	struct mapping zero = { 0 };
	*out_mapping = zero;
	char *newline;
	for (;;) {
		newline = (char *)fs_memchr(&f->buf[f->buf_offset], '\n', f->count);
		if (newline) {
			break;
		}
		if (f->buf_offset > (int)sizeof(f->buf) / 4) {
			fs_memmove(f->buf, &f->buf[f->buf_offset], f->count);
			f->buf_offset = 0;
		}
		int starting_pos = f->buf_offset + f->count;
		if (starting_pos == sizeof(f->buf)) {
			return -ENOMEM;
		}
		intptr_t result = fs_read(fd, &f->buf[starting_pos], sizeof(f->buf) - starting_pos);
		if (result <= 0) {
			return result;
		}
		f->count += result;
	}
	*newline = '\0';
	bool result = read_mapping(&f->buf[f->buf_offset], out_mapping);
	int consumed = (newline - &f->buf[f->buf_offset]) + 1;
	f->count -= consumed;
	f->buf_offset += consumed;
	return result == true;
}
