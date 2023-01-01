#ifndef TARGET_H
#define TARGET_H

#include <stdint.h>

typedef struct {
	uint16_t nr;
	uint8_t is_in;
	uint8_t is_out;
} __attribute__((packed)) syscall_template;

#define TARGET_NO_RESPONSE ((uint16_t)1 << 15)
#define TARGET_NR_PEEK (TARGET_NO_RESPONSE-1)
#define TARGET_NR_POKE (TARGET_NO_RESPONSE | TARGET_NR_PEEK)
#define TARGET_NR_CALL (TARGET_NO_RESPONSE-2)
#define TARGET_NR_GET_PROCESS_DATA_ADDRESS (TARGET_NO_RESPONSE-3)

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

enum target_platform {
	TARGET_PLATFORM_LINUX,
	TARGET_PLATFORM_DARWIN,
};

typedef struct {
	uint32_t server_fd;
	uint8_t target_platform;
} __attribute__((packed)) hello_message;

#endif
