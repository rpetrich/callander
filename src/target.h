#ifndef TARGET_H
#define TARGET_H

#include <stdint.h>

#include "freestanding.h"

typedef struct {
	struct fs_mutex read_mutex __attribute__((aligned(64)));
	struct fs_mutex write_mutex __attribute__((aligned(64)));
	int sockfd __attribute__((aligned(64)));
} target_state;

typedef struct {
	uint16_t nr;
	uint8_t is_in;
	uint8_t is_out;
} __attribute__((packed)) syscall_template;

#define TARGET_NO_RESPONSE ((uint16_t)1 << 15)
#define TARGET_NR_PEEK (TARGET_NO_RESPONSE-1)
#define TARGET_NR_POKE (TARGET_NO_RESPONSE | TARGET_NR_PEEK)
#define TARGET_NR_CALL (TARGET_NO_RESPONSE-2)

typedef struct {
	syscall_template template;
	uint32_t id;
	uint64_t values[6];
	char address_data[0];
} __attribute__((packed)) request_message;

typedef struct {
	uint64_t result;
	uint32_t id;
	char address_data[0];
} __attribute__((packed)) response_message;

typedef struct {
	response_message header;
	request_message request;
} __attribute__((packed)) client_request;

enum target_platform {
	TARGET_PLATFORM_LINUX,
	TARGET_PLATFORM_DARWIN,
};

typedef struct {
	uint8_t target_platform;
	target_state *state;
	void (*process_data)(void);
} __attribute__((packed)) hello_message;

#endif
