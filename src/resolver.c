#include "resolver.h"

#include "proxy.h"

#include <string.h>

static in_port_t parse_service(const char *service)
{
	if (service == NULL) {
		return 0;
	}
	if (fs_strcmp(service, "ftp") == 0) {
		return 21;
	}
	if (fs_strcmp(service, "ssh") == 0) {
		return 22;
	}
	if (fs_strcmp(service, "telnet") == 0) {
		return 23;
	}
	if (fs_strcmp(service, "nameserver") == 0) {
		return 42;
	}
	if (fs_strcmp(service, "whois") == 0) {
		return 43;
	}
	if (fs_strcmp(service, "domain") == 0) {
		return 53;
	}
	if (fs_strcmp(service, "http") == 0) {
		return 80;
	}
	if (fs_strcmp(service, "https") == 0) {
		return 443;
	}
	intptr_t result = 0;
	if (fs_scans(service, &result) == NULL) {
		return 0;
	}
	return (in_port_t)result;
}

static int inet_aton_simple(const char *buf, struct in_addr *out_addr)
{
	// not a full implementation of inet_aton
	union result {
		struct in_addr addr;
		uint8_t bytes[4];
	} data;
	intptr_t value;
	const char *next = fs_scans(buf, &value);
	if (*next != '.' || (uintptr_t)value > 0xff) {
		return 0;
	}
	data.bytes[0] = value;
	next = fs_scans(next + 1, &value);
	if (*next != '.' || (uintptr_t)value > 0xff) {
		return 0;
	}
	data.bytes[1] = value;
	next = fs_scans(next + 1, &value);
	if (*next != '.' || (uintptr_t)value > 0xff) {
		return 0;
	}
	data.bytes[2] = value;
	next = fs_scans(next + 1, &value);
	if (*next != '\0' || (uintptr_t)value > 0xff) {
		return 0;
	}
	data.bytes[3] = value;
	*out_addr = data.addr;
	return 1;
}

static int dns_resolver_address(struct resolver_funcs funcs, struct sockaddr_in *out_addr)
{
	uint32_t result = atomic_load_explicit(&funcs.config_cache->address, memory_order_relaxed);
	if (result == 0) {
		int fd = funcs.openat(AT_FDCWD, "/etc/resolv.conf", O_RDONLY, 0);
		if (fd < 0) {
			return fd;
		}
		char buf[1024];
		int cursor = 0;
		for (;;) {
			const char *line_start = buf;
			int read = funcs.read(fd, &buf[cursor], sizeof(buf) - cursor);
			if (read < 0) {
				funcs.close(fd);
				return read;
			}
			cursor += read;
			for (;;) {
				const char *newline = fs_memchr(line_start, '\n', &buf[cursor] - line_start);
				if (newline == NULL && read != 0) {
					break;
				}
				const char *next_line = newline == NULL ? &buf[cursor] : newline;
				if (next_line - line_start > (ssize_t)sizeof("nameserver ") - 1 && fs_memcmp(line_start, "nameserver ", sizeof("nameserver ") - 1) == 0) {
					char nameserver_buf[256];
					size_t addr_size = next_line - line_start - (sizeof("nameserver ") - 1);
					if (addr_size < sizeof(nameserver_buf) - 1) {
						memcpy(&nameserver_buf, line_start + sizeof("nameserver ") - 1, addr_size);
						nameserver_buf[addr_size] = '\0';
						struct in_addr addr;
						if (inet_aton_simple(nameserver_buf, &addr) == 0) {
							funcs.close(fd);
							return -EINVAL;
						}
						result = addr.s_addr;
					}
				}
				if (newline == NULL) {
					break;
				}
				line_start = newline + 1;
			}
			if (read == 0) {
				break;
			}
			ssize_t offset = line_start - &buf[0];
			if (offset > 0) {
				fs_memmove(&buf[0], line_start, cursor - offset);
				cursor -= offset;
			}
		}
		funcs.close(fd);
		if (result == 0) {
			return -EINVAL;
		}
		atomic_store_explicit(&funcs.config_cache->address, result, memory_order_relaxed);
	}
	*out_addr = (struct sockaddr_in){
		.sin_family = AF_INET,
		.sin_port = hton_16(53),
		.sin_addr = (struct in_addr){result},
		.sin_zero = {0},
	};
	return 0;
}

#define QR_QUERY 0
#define QR_RESPONSE 1

#define OPCODE_QUERY 0
#define OPCODE_IQUERY 1
#define OPCODE_STATUS 2

#define T_A 1 // Ipv4 address
#define T_NS 2 // Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 // Mail server

__attribute__((packed)) __attribute__((aligned(1))) struct dns_header
{
	unsigned short id; // identification number

	unsigned char rd : 1; // recursion desired
	unsigned char tc : 1; // truncated message
	unsigned char aa : 1; // authoritive answer
	unsigned char opcode : 4; // purpose of message
	unsigned char qr : 1; // query/response flag

	unsigned char rcode : 4; // response code
	unsigned char cd : 1; // checking disabled
	unsigned char ad : 1; // authenticated data
	unsigned char z : 1; // its z! reserved
	unsigned char ra : 1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

__attribute__((packed)) __attribute__((aligned(1))) struct dns_query
{
	unsigned short qtype;
	unsigned short qclass;
};

__attribute__((packed)) __attribute__((aligned(1))) struct dns_record
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};

static int populate_addrinfo(struct sockaddr *addr, struct resolver_funcs funcs, struct addrinfo **res)
{
	struct addrinfo *result = funcs.malloc(sizeof(struct addrinfo));
	if (result == NULL) {
		funcs.free(addr);
		return EAI_MEMORY;
	}
	result->ai_flags = 0;
	result->ai_family = addr->sa_family;
	result->ai_socktype = SOCK_STREAM;
	result->ai_protocol = IPPROTO_TCP;
	result->ai_addrlen = sizeof(struct sockaddr_in6);
	result->ai_addr = (struct sockaddr *)addr;
	result->ai_canonname = NULL;
	result->ai_next = *res;
	*res = result;
	return 0;
}

static struct sockaddr_in6 *make_sockaddr_in6(struct in6_addr addr, in_port_t port, struct resolver_funcs funcs)
{
	struct sockaddr_in6 *result = funcs.malloc(sizeof(struct sockaddr_in6));
	if (result == NULL) {
		return NULL;
	}
	result->sin6_family = AF_INET6;
	result->sin6_port = hton_16(port);
	result->sin6_flowinfo = 0;
	result->sin6_scope_id = 0;
	result->sin6_addr = addr;
	return result;
}

static struct sockaddr_in *make_sockaddr_in(struct in_addr addr, in_port_t port, struct resolver_funcs funcs)
{
	struct sockaddr_in *result = funcs.malloc(sizeof(struct sockaddr_in));
	if (result == NULL) {
		return NULL;
	}
	result->sin_family = AF_INET;
	result->sin_port = hton_16(port);
	result->sin_addr = addr;
	return result;
}

static int encode_qname(const char *name, char *out_buf, size_t size, int *out_bytes_used)
{
	int cur = 0;
	for (int i = 0;;) {
		if (name[i] == '.') {
			out_buf[cur] = i - cur;
			cur = i + 1;
		} else if (name[i] == '\0') {
			out_buf[cur] = i - cur;
			cur = i + 1;
			break;
		} else {
			out_buf[i + 1] = name[i];
		}
		i++;
		if (i == (int)size - 1) {
			return EAI_MEMORY;
		}
	}
	// terminate with a null byte
	out_buf[cur++] = '\0';
	*out_bytes_used = cur;
	return 0;
}

static int decode_qname_length(const char *buf, size_t size)
{
	for (int i = 0; i < (int)size;) {
		uint8_t c = (uint8_t)buf[i];
		if (c == 0) {
			return i + 1;
		} else if (c >= 192) {
			return i + 2;
		}
		i += c + 1;
	}
	return size;
}

int getaddrinfo_custom(const char *node, const char *service, __attribute__((unused)) const struct addrinfo *hints, struct resolver_funcs funcs, struct addrinfo **res)
{
	in_port_t parsed_service = parse_service(service);
	if (parsed_service == 0) {
		return EAI_SERVICE;
	}
	if (fs_strcmp(node, "localhost") == 0) {
		return populate_addrinfo((struct sockaddr *)make_sockaddr_in((struct in_addr){127 | (1 << 24)}, parsed_service, funcs), funcs, res);
	}
	if (fs_strcmp(node, "ip6-localhost") == 0 || fs_strcmp(node, "ip6-loopback") == 0) {
		struct in6_addr addr;
		addr.s6_addr[0] = 0;
		addr.s6_addr[1] = 0;
		addr.s6_addr[2] = 0;
		addr.s6_addr[3] = 0;
		addr.s6_addr[4] = 0;
		addr.s6_addr[5] = 0;
		addr.s6_addr[6] = 0;
		addr.s6_addr[7] = 0;
		addr.s6_addr[8] = 0;
		addr.s6_addr[9] = 0;
		addr.s6_addr[10] = 0;
		addr.s6_addr[11] = 0;
		addr.s6_addr[12] = 0;
		addr.s6_addr[13] = 0;
		addr.s6_addr[14] = 0;
		addr.s6_addr[15] = 1;
		return populate_addrinfo((struct sockaddr *)make_sockaddr_in6(addr, parsed_service, funcs), funcs, res);
	}
	struct sockaddr_in nameserver;
	int result = dns_resolver_address(funcs, &nameserver);
	if (result < 0) {
		*funcs.errno_location = -result;
		return EAI_SYSTEM;
	}
	int fd = funcs.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		*funcs.errno_location = -fd;
		return EAI_SYSTEM;
	}
	struct
	{
		struct dns_header header;
		char data[65536 - sizeof(struct dns_header)];
	} request;
	request.header = (struct dns_header){0};
	request.header.id = 2048;
	request.header.rd = 1;
	request.header.q_count = hton_16(1);
	int name_len = 0;
	result = encode_qname(node, &request.data[0], sizeof(request.data), &name_len);
	if (result != 0) {
		return result;
	}
	struct dns_query *query = (struct dns_query *)&request.data[name_len];
	query->qtype = hton_16(T_A);
	query->qclass = hton_16(1);
	size_t request_len = sizeof(struct dns_header) + name_len + sizeof(struct dns_query);
	result = funcs.sendto(fd, (const void *)&request, request_len, 0, (const struct sockaddr *)&nameserver, sizeof(nameserver));
	if (result < 0) {
		funcs.close(fd);
		*funcs.errno_location = -result;
		return EAI_SYSTEM;
	}
	int response_size = funcs.recvfrom(fd, (void *)&request, sizeof(request), 0, NULL, 0);
	funcs.close(fd);
	if (response_size < 0) {
		*funcs.errno_location = -response_size;
		return EAI_SYSTEM;
	}
	if (hton_16(request.header.ans_count) == 0) {
		return EAI_NONAME;
	}
	int record_pos = decode_qname_length(request.data, sizeof(request.data)) + sizeof(*query);
	// int record_pos = request_len - sizeof(struct dns_header);
	struct addrinfo *records = NULL;
	while (record_pos + sizeof(struct dns_record) <= (uintptr_t)response_size) {
		record_pos += decode_qname_length(&request.data[record_pos], sizeof(request.data) - record_pos);
		const struct dns_record *record = (const struct dns_record *)&request.data[record_pos];
		size_t data_len = hton_16(record->data_len);
		if (record_pos + data_len + sizeof(request.header) > (size_t)response_size) {
			break;
		}
		// use 10 instead of sizeof(struct dns_record) because of padding
		if (record->type == hton_16(T_A) && data_len == 4) {
			struct in_addr addr;
			fs_memcpy(&addr, &request.data[record_pos + 10], 4);
			result = populate_addrinfo((struct sockaddr *)make_sockaddr_in(addr, parsed_service, funcs), funcs, &records);
			if (result != 0) {
				if (records == NULL) {
					return result;
				}
				break;
			}
		}
		record_pos += 10 + data_len;
	}
	if (records != NULL) {
		*res = records;
		return 0;
	}
	return EAI_NONAME;
}
