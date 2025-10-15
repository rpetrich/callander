#ifndef LOADER_H
#define LOADER_H

#include "freestanding.h"
#if defined(__APPLE__)
#include "elf.h"
#else
#include <elf.h>
#endif
#include <stdbool.h>
#include <stdint.h>

#ifdef __LP64__
#define CURRENT_CLASS ELFCLASS64
#define ElfW(type) Elf64_##type
#else
#define CURRENT_CLASS ELFCLASS32
#define ElfW(type) Elf32_##type
#endif

#define DW_EH_PE_omit 0xff
#define DW_EH_PE_ptr 0x00

#define DW_EH_PE_uleb128 0x01
#define DW_EH_PE_udata2 0x02
#define DW_EH_PE_udata4 0x03
#define DW_EH_PE_udata8 0x04
#define DW_EH_PE_sleb128 0x09
#define DW_EH_PE_sdata2 0x0a
#define DW_EH_PE_sdata4 0x0b
#define DW_EH_PE_sdata8 0x0c
#define DW_EH_PE_signed 0x09

#define DW_EH_PE_absptr 0x00
#define DW_EH_PE_pcrel 0x10
#define DW_EH_PE_textrel 0x20
#define DW_EH_PE_datarel 0x30

enum
{
	EXECUTABLE_STACK_DEFAULT,
	EXECUTABLE_STACK_REQUIRED,
	EXECUTABLE_STACK_PROHIBITED,
};

// binary_info represents information about a loaded binary
struct binary_info
{
	void *base;
	size_t size;
	void *entrypoint;
	void *default_base;
	void *program_header;
	size_t header_entry_size;
	size_t header_entry_count;
	const ElfW(Dyn) * dynamic;
	size_t dynamic_size;
	size_t dynamic_offset;
	size_t section_offset;
	size_t section_entry_size;
	size_t section_entry_count;
	int strtab_section_index;
	int executable_stack;
	const char *interpreter;
	size_t relro_vaddr;
	size_t relro_memsz;
	int relro_pflags;
};

// load_binary will load and map the binary in fd into the process' address space
__attribute__((warn_unused_result)) extern int load_binary(int fd, struct binary_info *out_info, uintptr_t load_address, bool force_relocation);

__attribute__((warn_unused_result)) extern int load_binary_with_layout(const ElfW(Ehdr) * header, const ElfW(Phdr) * program_header, int fd, size_t file_offset, size_t size, struct binary_info *out_info, uintptr_t load_address,
                                                                       int force_relocation);

// unload_binary will unmap the binary from the process' address space
extern void unload_binary(struct binary_info *info);

// load_existing will attempt to load info about an already loaded binary
extern void load_existing(struct binary_info *out_info, uintptr_t load_address);

extern int load_main_from_auxv(const ElfW(auxv_t) * aux, struct binary_info *out_info);
extern int load_interpreter_from_auxv(const ElfW(auxv_t) * aux, struct binary_info *out_info);

// relocate_binary will apply relocation fixups to a loaded binary
extern void relocate_binary(struct binary_info *info);

// relocate_main_from_auxv will apply relocation fixups to the main binary specified in an auxiliary vector
extern void relocate_main_from_auxv(const ElfW(auxv_t) * aux);

// apply_postrelocation_readonly will make any pages marked readonly after relocation readonly
extern int apply_postrelocation_readonly(struct binary_info *info);

// apply_base_address calculates the mapped equivalent of an address specified in the binary, applying relocation if necessary
__attribute__((always_inline)) static inline intptr_t apply_base_address(const struct binary_info *info, intptr_t addr_or_offset)
{
	return (intptr_t)(info->base - info->default_base) + addr_or_offset;
}

struct symbol_version_info
{
	const char *version_name;
	const char *library_name;
	const struct symbol_version_info *next;
};

// symbol_info represents information about a loaded binary
struct symbol_info
{
	const ElfW(Word) * buckets;
	size_t bucket_count;
	uintptr_t symbols;
	size_t symbol_stride;
	size_t symbol_count;
	const ElfW(Word) * chains;
	void *gnu_hash;
	const char *strings;
	size_t strings_size;
	const void **init_functions;
	size_t init_function_count;
	void *mapping;
	size_t mapping_size;
	void *address_ordered;
	const ElfW(Half) * symbol_versions;
	struct symbol_version_info *valid_versions;
	size_t valid_version_count;
};
// load_dynamic_symbols will map in the symbols for a loaded binary and parse them
__attribute__((warn_unused_result)) extern int load_dynamic_symbols(int fd, const struct binary_info *info, struct symbol_info *out_symbols);
// parse_dynamic_symbols will parse dynamic symbols into a symbol struct
__attribute__((warn_unused_result)) extern int parse_dynamic_symbols(const struct binary_info *info, void *mapped_address, struct symbol_info *out_symbols);

struct section_info;
// load_section_symbols will map in the symbols for a particular section in a loaded binary and parse them
__attribute__((warn_unused_result)) int load_section_symbols(int fd, struct binary_info *info, const struct section_info *section_info, bool load_hash, struct symbol_info *out_symbols);
// free_symbols will cleanup the loaded symbol data
extern void free_symbols(struct symbol_info *symbols);
// symbol_name validates and returns a symbol name
const char *symbol_name(const struct symbol_info *symbols, const ElfW(Sym) * symbol);

// find_symbol looks up a symbol by name
extern void *find_symbol(const struct binary_info *info, const struct symbol_info *symbols, const char *symbol_name, const char *version_name, const ElfW(Sym) * *out_symbol);
// find_next_symbol looks up the next symbol by name
__attribute__((warn_unused_result)) extern void *find_next_symbol(const struct binary_info *info, const struct symbol_info *symbols, const char *symbol_name, const ElfW(Sym) * *symbol);
// find_symbol_by_address looks up a symbol by internal address
__attribute__((warn_unused_result)) extern void *find_symbol_by_address(const struct binary_info *info, const struct symbol_info *symbols, const void *addr, const ElfW(Sym) * *out_symbol);
// symbol_info_contains_symbol checks if a symbol is part of a symbol table
bool symbol_info_contains_symbol(const struct symbol_info *symbols, const ElfW(Sym) * symbol);

__attribute__((always_inline)) static inline struct symbol_version_info symbol_version_for_index(const struct symbol_info *symbols, ElfW(Half) index)
{
	if (index >= 2 && index < symbols->valid_version_count) {
		return symbols->valid_versions[index];
	}
	return (struct symbol_version_info){0};
}

struct section_info
{
	const ElfW(Shdr) * sections;
	const char *strings;
};

// load_section_info loads the section info
__attribute__((warn_unused_result)) extern int load_section_info(int fd, const struct binary_info *info, struct section_info *out_section_info);
// free_section_info cleans up the section info
extern void free_section_info(const struct section_info *section_info);

// find_section looks up a section by name
__attribute__((warn_unused_result)) const ElfW(Shdr) * find_section(const struct binary_info *info, const struct section_info *section_info, const char *name);

// elf_hash implements the standard hashing algorithm defined in the ELF
// specification
unsigned long elf_hash(const unsigned char *name);

// gnu_hash implements the GNU hashing algorithm defined who knows where
uint32_t gnu_hash(const char *name);

// _DYNAMIC is a reference to the current binary's PT_DYNAMIC section
// this is a special symbol filled in by the linker
extern ElfW(Dyn) _DYNAMIC[] __attribute__((visibility("hidden")));

// verify_allowed_to_exec verifies that the target file is executable by the current user/group
__attribute__((warn_unused_result)) int verify_allowed_to_exec(int fd, struct fs_stat *stat, uid_t uid, gid_t gid);

struct frame_info
{
	void *data;
	uintptr_t data_base_address;
	uintptr_t text_base_address;
	bool supported_eh_frame_hdr;
};

struct eh_frame_hdr
{
	uint8_t version;
	uint8_t eh_frame_ptr_enc;
	uint8_t fde_count_enc;
	uint8_t table_enc;
	char data[];
};

__attribute__((warn_unused_result)) int load_frame_info_from_section(int fd, const struct binary_info *binary, const struct section_info *section_info, struct frame_info *out_info);
int load_frame_info_from_program_header(const struct binary_info *binary, const struct eh_frame_hdr *data, struct frame_info *out_info);
void free_frame_info(struct frame_info *info);

struct frame_details
{
	const void *address;
	size_t size;
};
bool find_containing_frame_info(struct frame_info *info, const void *address, struct frame_details *out_frame);

uintptr_t read_uleb128(void **cursor);
intptr_t read_sleb128(void **cursor);

uintptr_t read_eh_frame_value(void **cursor, unsigned char encoding);
uintptr_t read_eh_frame_pointer(const struct frame_info *frame_info, void **cursor, unsigned char encoding);

#endif
