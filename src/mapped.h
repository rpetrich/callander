#ifndef MAPPED_H
#define MAPPED_H

#include "tls.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#ifdef __linux__
#include <linux/limits.h>
#else
#include <sys/syslimits.h>
#endif

// region_is_mapped checks if a particular address is mapped. this is inherently
// racy since the workload could immediatly map or unmap the address shortly
// after the check occurs
__attribute__((warn_unused_result))
bool region_is_mapped(struct thread_storage *thread, const void *address, size_t length);

struct mapping {
	void *start;
	void *end;
	uintptr_t offset;
	dev_t device;
	ino_t inode;
	uint8_t prot;
	uint8_t flags;
	char path[PATH_MAX];
};

// lookup_mapping_for_address finds the mapping associated with the address
__attribute__((warn_unused_result))
int lookup_mapping_for_address(const void *address, struct mapping *out_mapping);

struct maps_file_state {
	int buf_offset;
	int count;
	char buf[8192];
};

void init_maps_file_state(struct maps_file_state *out_maps_file);

__attribute__((warn_unused_result))
int read_next_mapping_from_file(int fd, struct maps_file_state *maps_file, struct mapping *out_mapping);

#endif
