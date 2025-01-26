#include "callander.h"
#include "callander_print.h"
#include "ins.h"

#include <elf.h>
#include <dirent.h>
#include <linux/audit.h>
#include <linux/binfmts.h>
#include <linux/seccomp.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#ifdef __linux__
#include <linux/limits.h>
#else
#include <sys/syslimits.h>
#endif
#include <sys/user.h>

#include "bpf_debug.h"
#include "exec.h"
#include "ins.h"
#include "dlmalloc.h"
#include "freestanding.h"
#include "axon.h"
#include "loader.h"
#include "mapped.h"
#include "qsort.h"
#include "search.h"

AXON_BOOTSTRAP_ASM

#define PRINT_GDB_COMMANDS 1

struct embedded_binary {
	uint32_t name;
	uint32_t text_address;
};

struct bootstrap_offsets {
	uint32_t base_to_bootstrap_dynamic;
	uint32_t real_program_header;
	uint32_t interpreter_base;
	uint32_t main_entrypoint;
	ElfW(Ehdr) header;
	bool remap_binary;
#if PRINT_GDB_COMMANDS
	struct embedded_binary embedded_binaries[PAGE_SIZE/sizeof(struct embedded_binary)];
#endif
};

static struct bootstrap_offsets bootstrap_offsets = { .base_to_bootstrap_dynamic = -1 };

__attribute__((visibility("hidden")))
__attribute__((used))
noreturn void bootstrap_interpreter(size_t *sp)
{
	// find environment
	char **argv = (void *)(sp+1);
	char **current_argv = argv;
	while (*current_argv != NULL) {
		++current_argv;
	}
	// find auxiliary vector
	char **envp = current_argv+1;
	char **current_envp = envp;
	while (*current_envp != NULL) {
		++current_envp;
	}
	// patch auxiliary vector
	uintptr_t base = (uintptr_t)&_DYNAMIC - bootstrap_offsets.base_to_bootstrap_dynamic;
	for (ElfW(auxv_t) *aux = (ElfW(auxv_t) *)(current_envp + 1); aux->a_type != AT_NULL; aux++) {
		switch (aux->a_type) {
			case AT_BASE: {
				// patch AT_BASE to point to the interpreter
				aux->a_un.a_val = base + bootstrap_offsets.interpreter_base;
				break;
			}
			case AT_ENTRY: {
				// patch AT_ENTRY to point to the main entrypoint
				aux->a_un.a_val = base + bootstrap_offsets.main_entrypoint;
				break;
			}
			case AT_PHDR: {
				// patch AT_PHDR to point to the new program headers
				aux->a_un.a_val = base + bootstrap_offsets.real_program_header;
				break;
			}
			case AT_PHNUM: {
				// patch AT_PHNUM to reflect the new program header count
				aux->a_un.a_val = bootstrap_offsets.header.e_phnum;
				break;
			}
		}
	}
	// remap the binary using the embedded program header, if required
	if (bootstrap_offsets.remap_binary) {
		int fd = fs_open("/proc/self/exe", O_RDONLY, 0);
		if (fd < 0) {
			DIE("unable to open self", fs_strerror(fd));
		}
		struct binary_info info;
		bootstrap_offsets.header.e_phnum -= 3;
		int result = load_binary_with_layout(&bootstrap_offsets.header, fd, 0, -1, &info, base, 2);
		bootstrap_offsets.header.e_phnum += 3;
		if (result < 0) {
			DIE("unable to load", fs_strerror(result));
		}
		fs_close(fd);
	}
#if 0
	// patch the ELF header
	int result = fs_mprotect((void *)base, PAGE_SIZE, PROT_READ|PROT_WRITE);
	if (result < 0) {
		DIE("failed to remap writable", fs_strerror(result));
	}
	*(ElfW(Ehdr) *)base = bootstrap_offsets.header;
	result = fs_mprotect((void *)base, PAGE_SIZE, PROT_READ|PROT_EXEC);
	if (result < 0) {
		DIE("failed to remap executable", fs_strerror(result));
	}
#endif
#if PRINT_GDB_COMMANDS
	// print gdb commands to force it to load symbols
	char buf[PATH_MAX];
	fs_memcpy(buf, "add-symbol-file ", sizeof("add-symbol-file ")-1);
	for (size_t i = 0; i < sizeof(bootstrap_offsets.embedded_binaries)/sizeof(bootstrap_offsets.embedded_binaries[0]); i++) {
		if (bootstrap_offsets.embedded_binaries[i].name == 0) {
			break;
		}
		size_t c = sizeof("add-symbol-file ")-1;
		const char *name = (const char *)base + bootstrap_offsets.embedded_binaries[i].name;
		size_t name_len = fs_strlen(name);
		fs_memcpy(&buf[c], name, name_len);
		c += name_len;
		buf[c++] = ' ';
		c += fs_utoah(base + bootstrap_offsets.embedded_binaries[i].text_address, &buf[c]);
		buf[c++] = '\n';
		ERROR_WRITE(buf, c);
	}
	ERROR_FLUSH();
#endif
	// jump to the embedded ELF interpreter's entrypoint
	void *interpreter_base = (void *)(base + bootstrap_offsets.interpreter_base);
	const ElfW(Ehdr) *interpreter_header = interpreter_base;
	void *interpreter_entrypoint = interpreter_base + interpreter_header->e_entry;
	JUMP(interpreter_entrypoint, sp, 0, 0, 0);
}

AXON_ENTRYPOINT_TRAMPOLINE_ASM(bootstrap_trampoline, bootstrap_interpreter);
void bootstrap_trampoline(void);

static bool bundle_interpreter = true;
static bool remap_binary = true;

static bool should_include_binary(struct loaded_binary *binary)
{
	return (binary->special_binary_flags & BINARY_IS_LOADED_VIA_DLOPEN) == 0
		&& fs_strcmp(binary->loaded_path, "[vdso]") != 0
		&& (bundle_interpreter || (binary->special_binary_flags & BINARY_IS_INTERPRETER) == 0);
}

#define ALIGN_UP(value, alignment) (((value) + alignment - 1) & ~(alignment - 1))
#define EXECUTABLE_BASE_ALIGN 0x10000

__attribute__((unused))
static size_t file_offset_for_binary(struct loader_context *loader, const struct loaded_binary *source_binary)
{
	size_t offset = 0;
	for (struct loaded_binary *binary = loader->main; binary != NULL; binary = binary->previous) {
		if (should_include_binary(binary)) {
			if (binary == source_binary) {
				return offset;
			}
			offset += ALIGN_UP(binary->size, PAGE_SIZE);
		}
	}
	return -1;
}

__attribute__((unused))
static size_t file_offset_for_binary_address(struct loaded_binary *binary, intptr_t address)
{
	const ElfW(Phdr) *phdr = binary->info.program_header;
	for (ElfW(Word) i = 0; i < binary->info.header_entry_count; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			ElfW(Addr) end = phdr[i].p_vaddr + phdr[i].p_memsz;
			if (address >= phdr[i].p_vaddr && address < end) {
				return phdr[i].p_offset + address - phdr[i].p_vaddr;
			}
		}
	}
	return -1;
}

__attribute__((unused))
static size_t address_for_binary(struct loader_context *loader, const struct loaded_binary *source_binary)
{
	size_t address = 0;
	for (struct loaded_binary *binary = loader->main; binary != NULL; binary = binary->previous) {
		if (should_include_binary(binary)) {
			if (binary == source_binary) {
				return address;
			}
			size_t largest_addr = 0;
			const ElfW(Phdr) *phdr = binary->info.program_header;
			for (ElfW(Word) i = 0; i < binary->info.header_entry_count; i++) {
				if (phdr[i].p_type == PT_LOAD) {
					ElfW(Addr) end = phdr[i].p_vaddr + phdr[i].p_memsz;
					if (end > largest_addr) {
						largest_addr = end;
					}
				}
			}
			address += ALIGN_UP(largest_addr, EXECUTABLE_BASE_ALIGN);
		}
	}
	return -1;
}

enum ordering_class {
	ORDERING_CLASS_LOCAL = 0,
	ORDERING_CLASS_UNDEFINED = 1,
	ORDERING_CLASS_DEFINED = 2,
};

static inline enum ordering_class ordering_class_for_sym(const ElfW(Sym) *sym)
{
	if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL) {
		return ORDERING_CLASS_LOCAL;
	}
	if (sym->st_shndx == 0) {
		return ORDERING_CLASS_UNDEFINED;
	}
	return ORDERING_CLASS_DEFINED;
}

struct symbol_ordering {
	struct loaded_binary *binary;
	uint32_t source_index;
	uint32_t gnu_hash;
	uint32_t address_offset;
	uint32_t strings_offset;
	uint32_t tls_offset;
};

static const ElfW(Sym) *symbol_for_ordering_entry(const struct symbol_ordering *entry)
{
	return (const void *)entry->binary->symbols.symbols + entry->source_index * entry->binary->symbols.symbol_stride;
}

__attribute__((unused))
static inline int compare_symbol_ordering(const void *left_untyped, const void *right_untyped, __attribute__((unused)) void *data)
{
	const struct symbol_ordering *left = left_untyped;
	const struct symbol_ordering *right = right_untyped;
	const ElfW(Sym) *left_sym = symbol_for_ordering_entry(left);
	const ElfW(Sym) *right_sym = symbol_for_ordering_entry(right);
	enum ordering_class left_class = ordering_class_for_sym(left_sym);
	enum ordering_class right_class = ordering_class_for_sym(right_sym);
	// sort first by ordering class
	if (left_class < right_class) {
		return -1;
	}
	if (left_class > right_class) {
		return 1;
	}
	if (left_class == ORDERING_CLASS_DEFINED) {
		// if both are defined symbols, sort by gnu hash
		if (left->gnu_hash < right->gnu_hash) {
			return -1;
		}
		if (left->gnu_hash > right->gnu_hash) {
			return 1;
		}
	} else {
		// otherwise sort in binary order
		if (left->address_offset < right->address_offset) {
			return -1;
		}
		if (left->address_offset > right->address_offset) {
			return 1;
		}
		// then in the original order from the source binary
		if (left->source_index < right->source_index) {
			return -1;
		}
		if (left->source_index > right->source_index) {
			return 1;
		}
	}
	return 0;
}

static void copy_relas(const struct loaded_binary *binary, ElfW(Rela) **relas, uintptr_t rela, size_t relasz, size_t relaent, ssize_t address_offset, size_t alternate_range_start, size_t alternate_range_size, ssize_t alternate_offset, ssize_t tls_offset, const struct symbol_ordering *symbol_ordering, size_t symbol_count)
{
	void *relbase = (void *)apply_base_address(&binary->info, rela);
	for (uintptr_t rel_off = 0; rel_off < relasz; rel_off += relaent) {
		const ElfW(Rela) *rel = relbase + rel_off;
		uintptr_t info = rel->r_info;
		Elf64_Word symbol_index = ELF64_R_SYM(info);
		if (symbol_index != 0) {
			for (size_t i = 0; i < symbol_count; i++) {
				if (symbol_ordering[i].source_index == symbol_index && symbol_ordering[i].binary == binary) {
					info = ELF64_R_INFO(i, ELF64_R_TYPE(info));
					break;
				}
			}
		}
		ssize_t offset = (rel->r_offset >= alternate_range_start) && (rel->r_offset < alternate_range_start + alternate_range_size) ? alternate_offset : address_offset;
		uintptr_t addend_offset;
		switch (ELF64_R_TYPE(info)) {
			// case INS_R_COPY:
			// 	ERROR("COPY relocations are not supported");
			// 	(*relas)++;
			// 	continue;
			case INS_R_RELATIVE:
			case INS_R_IRELATIVE:
				addend_offset = address_offset;
				break;
			case INS_R_TLSDESC:
				addend_offset = tls_offset;
				break;
			case INS_R_TLS_DTPREL:
			case INS_R_TLS_TPREL:
				// TODO: perform symbol lookup if symbol lookup is specified
				addend_offset = tls_offset;
				break;
			default:
				addend_offset = 0;
				break;
		}
		*(*relas)++ = (ElfW(Rela)) {
			.r_offset = rel->r_offset + offset,
			.r_info = info,
			.r_addend = rel->r_addend + addend_offset,
		};
	}
}

static void add_init_function(ElfW(Addr) *init_array, size_t *init_array_position, ElfW(Rela) **relas, ElfW(Addr) init_array_start, ElfW(Addr) init)
{
	size_t pos = *init_array_position;
	init_array[pos] = init;
	*(*relas)++ = (ElfW(Rela)) {
		.r_offset = init_array_start + pos * sizeof(ElfW(Addr)),
		.r_info = ELF64_R_INFO(0, ELF64_R_TYPE(INS_R_RELATIVE)),
		.r_addend = init,
	};
	*init_array_position = pos + 1;
}

static bool should_include_program_header(const struct loaded_binary *binary, const ElfW(Phdr) *phdr)
{
	switch (phdr->p_type) {
		case PT_LOAD:
			return true;
		case PT_TLS:
			return false;
		default:
			return (binary->special_binary_flags & BINARY_IS_MAIN) == BINARY_IS_MAIN;
	}
}

static bool should_preserve_headers_for_binary(const struct loaded_binary *binary, const struct loaded_binary *bootstrap)
{
	if (bootstrap == NULL || !remap_binary) {
		return true;
	}
	return (binary->special_binary_flags & (BINARY_IS_MAIN|BINARY_IS_INTERPRETER|BINARY_IS_LIBC|BINARY_IS_PTHREAD))
		|| binary == bootstrap;
}

static bool should_include_section(const struct loaded_binary *binary, const ElfW(Shdr) *section)
{
	if (binary->special_binary_flags & BINARY_IS_MAIN) {
		const char *name = &binary->sections.strings[section->sh_name];
		switch (section->sh_type) {
			case SHT_PROGBITS:
				if (fs_strcmp(name, ".gnu_debuglink") == 0 || fs_strcmp(name, ".gnu_debugaltlink") == 0 || fs_strcmp(name, ".eh_frame_hdr") == 0 || fs_strcmp(name, ".eh_frame") == 0) {
					return false;
				}
				return true;
			case SHT_NOTE:
				if (fs_strcmp(name, ".note.gnu.build-id") == 0) {
					return false;
				}
				return true;
			default:
				return true;
		}
	} else {
		return true;
		// switch (section->sh_type) {
		// 	case SHT_PROGBITS:
		// 		if (section->sh_flags & SHF_ALLOC) {
		// 			return true;
		// 		}
		// 		return false;
		// 	default:
		// 		return false;
		// }
	}
}

struct eh_frame_measurement {
	size_t full_size;
	size_t unterminated_size;
	size_t count;
};

__attribute__((noinline))
static struct eh_frame_measurement measure_eh_frame_section(void *data)
{
	size_t count = 0;
	size_t cie_offset = 0;
	for (;;) {
		void *current = data + cie_offset;
		// read length
		uint32_t length = *(const uint32_t *)current;
		if (length == 0) {
			break;
		}
		current += sizeof(uint32_t);
		// read cie_id
		uint32_t cie_id = *(const uint32_t *)current;
		// count
		count += cie_id != 0;
		// read length
		cie_offset += sizeof(uint32_t) + length;
	}
	return (struct eh_frame_measurement) {
		.full_size = cie_offset + sizeof(uint32_t),
		.unterminated_size = cie_offset,
		.count = count,
	};
}

__attribute__((noinline))
static void patch_eh_frames(void *data, int32_t pc_offset_diff, int32_t *search_table, int32_t binary_table_pc_offset_diff, int32_t binary_table_fde_offset_diff)
{
	unsigned char pointer_format = DW_EH_PE_ptr;
	size_t cie_offset = 0;
	for (;;) {
		void *current = data + cie_offset;
		// read length
		uint32_t length = *(const uint32_t *)current;
		if (length == 0) {
			break;
		}
		current += sizeof(uint32_t);
		// read cie_id
		uint32_t cie_id = *(const uint32_t *)current;
		current += sizeof(uint32_t);
		if (cie_id == 0) {
			// CIE
			// skip version
			current++;
			// skip augmentation
			bool has_pointer_format = false;
			for (;;) {
				char c = *(const char *)current++;
				if (c == '\0') {
					break;
				}
				if (c == 'R') {
					has_pointer_format = true;
				}
			}
			// skip code alignment factor
			read_uleb128(&current);
			// skip data alignment factor
			read_sleb128(&current);
			// skip return address register
			read_uleb128(&current);
			// read augmentation length
			if (has_pointer_format) {
				uintptr_t augmentation_length = read_uleb128(&current);
				// read pointer format
				pointer_format = ((const uint8_t *)current)[augmentation_length-1];
			} else {
				pointer_format = DW_EH_PE_ptr;
			}
		} else {
			// FDE
			// start
			uintptr_t pc = *(const int32_t *)current + (intptr_t)(current - data) + binary_table_pc_offset_diff;
			*search_table++ = pc;
			*search_table++ = cie_offset + binary_table_fde_offset_diff;
			if (pointer_format == (DW_EH_PE_pcrel|DW_EH_PE_sdata4)) {
				*(int32_t *)current += pc_offset_diff;
			} else {
				DIE("unexpected pointer encoding", (uintptr_t)pointer_format);
			}
		}
		// read length
		cie_offset += sizeof(uint32_t) + length;
	}
}

static size_t offset_for_self_symbol(const struct binary_info *self, const void *symbol)
{
	return ((ElfW(Addr))self->dynamic - (ElfW(Addr))self->base)
		+ ((ElfW(Addr))symbol - (ElfW(Addr))&_DYNAMIC);
}

static void write_combined_binary(struct program_state *analysis, struct loaded_binary *bootstrap)
{
	struct loaded_binary *main = analysis->loader.main;
	struct loaded_binary *interpreter = analysis->loader.interpreter;
	// count binaries
	size_t binary_count = 0;
	for (struct loaded_binary *binary = main; binary != NULL; binary = binary->previous) {
		binary_count += should_include_binary(binary);
	}
	// calculate new sizes
	size_t size = 0;
	ElfW(Addr) address_size = 0;
	size_t phcount = 1;
	size_t real_phcount = 0;
	size_t section_count = 0;
	size_t used_section_count = 0;
	size_t symbol_count = 1;
	size_t string_size = 0;
	size_t hash_size = sizeof(uint32_t) * 4 + sizeof(uint64_t) + sizeof(uint32_t);
	size_t rela_size = 0;
	size_t jmprel_size = 0;
	size_t preinit_array_size = 0;
	size_t init_array_size = 0;
	size_t fini_array_size = 0;
	struct loaded_binary *versioning_binary = NULL;
	ElfW(Addr) verdef = 0;
	size_t verdefnum = 0;
	ElfW(Addr) verneed = 0;
	size_t verneednum = 0;
	ssize_t last_set_eh_frame_index = -1;
	struct eh_frame_measurement *eh_frame_sizes = calloc(binary_count, sizeof(*eh_frame_sizes));
	size_t eh_frame_count = 0;
	size_t binary_index = 0;
	size_t main_binary_section_string_size = main->has_sections ? main->sections.sections[main->info.strtab_section_index].sh_size : 0;
	size_t shstrtab_size = main_binary_section_string_size;
	size_t tls_size = 0;
	size_t tls_alignment = 0;
	// calculate sizes of various output data
	for (struct loaded_binary *binary = main; binary != NULL; binary = binary->previous) {
		if (should_include_binary(binary)) {
			ElfW(Addr) largest_addr = 0;
			const ElfW(Phdr) *phdr = binary->info.program_header;
			size_t binary_tls_size = 0;
			for (ElfW(Word) i = 0; i < binary->info.header_entry_count; i++) {
				switch (phdr[i].p_type) {
					case PT_LOAD: {
						ElfW(Addr) end = phdr[i].p_vaddr + phdr[i].p_memsz;
						if (end > largest_addr) {
							largest_addr = end;
						}
						break;
					}
					case PT_GNU_EH_FRAME: {
						eh_frame_sizes[binary_index] = measure_eh_frame_section(binary->frame_info.data);
						eh_frame_count += eh_frame_sizes[binary_index].count;
						last_set_eh_frame_index = binary_index;
						break;
					}
					case PT_TLS: {
						if (phdr[i].p_align > tls_alignment) {
							tls_alignment = phdr[i].p_align;
						}
						tls_size = ALIGN_UP(tls_size, phdr[i].p_align);
						binary_tls_size = phdr[i].p_memsz;
						break;
					}
				}
				if (should_include_program_header(binary, &phdr[i])) {
					if (phdr[i].p_type == PT_INTERP) {
						if (bootstrap != NULL) {
							real_phcount++;
						} else {
							phcount++;
						}
					} else {
						if (should_preserve_headers_for_binary(binary, bootstrap)) {
							phcount++;
						}
						real_phcount++;
					}
				}
			}
			const ElfW(Shdr) *section = binary->sections.sections;
			section_count += binary->info.section_entry_count;
			size_t binary_path_len = fs_strlen(binary->path);
			for (size_t i = 0; i < binary->info.section_entry_count; i++) {
				if (should_include_section(binary, section)) {
					used_section_count++;
					if (binary != main) {
						const char *name = &binary->sections.strings[section->sh_name];
						shstrtab_size += fs_strlen(name) + 2 + binary_path_len;
					}
				}
				section = (void *)section + binary->info.section_entry_size;
			}
			if (binary != bootstrap && binary != interpreter) {
				const ElfW(Dyn) *dynamic = binary->info.dynamic;
				for (size_t i = 0; i < binary->info.dynamic_size; i++) {
					switch (dynamic[i].d_tag) {
						case DT_RELASZ:
							rela_size += dynamic[i].d_un.d_val;
							break;
						case DT_PLTRELSZ:
							jmprel_size += dynamic[i].d_un.d_val;
							break;
						case DT_PREINIT_ARRAYSZ:
							preinit_array_size += dynamic[i].d_un.d_val;
							break;
						case DT_INIT_ARRAYSZ:
							init_array_size += dynamic[i].d_un.d_val;
							break;
						case DT_INIT:
							init_array_size += sizeof(uintptr_t);
							break;
						case DT_FINI_ARRAYSZ:
							fini_array_size += dynamic[i].d_un.d_val;
							break;
						case DT_FINI:
							fini_array_size += sizeof(uintptr_t);
							break;
						case DT_VERSYM:
							if (binary->special_binary_flags & BINARY_IS_LIBC) {
								versioning_binary = binary;
							}
							break;
						case DT_VERDEF:
							if (binary->special_binary_flags & BINARY_IS_LIBC) {
								verdef = dynamic[i].d_un.d_ptr;
							}
							break;
						case DT_VERDEFNUM:
							if (binary->special_binary_flags & BINARY_IS_LIBC) {
								verdefnum = dynamic[i].d_un.d_val;
							}
							break;
						case DT_VERNEED:
							if (binary->special_binary_flags & BINARY_IS_LIBC) {
								verneed = dynamic[i].d_un.d_ptr;
							}
							break;
						case DT_VERNEEDNUM:
							if (binary->special_binary_flags & BINARY_IS_LIBC) {
								verneednum = dynamic[i].d_un.d_val;
							}
							break;
					}
				}
			}
			size += ALIGN_UP(binary->size, PAGE_SIZE);
			address_size += ALIGN_UP(largest_addr, EXECUTABLE_BASE_ALIGN);
			if (binary->has_symbols && binary != bootstrap && binary != interpreter) {
				symbol_count += binary->symbols.symbol_count - 1;
				// TODO: count only the defined symbols
				hash_size += (binary->symbols.symbol_count - 1) * sizeof(uint32_t);
				string_size += binary->symbols.strings_size;
			}
#if PRINT_GDB_COMMANDS
			string_size += fs_strlen(binary->loaded_path) + 1;
#endif
			tls_size += binary_tls_size;
			binary_index++;
		}
	}
	if (preinit_array_size | init_array_size | fini_array_size) {
		// allocate space for an additional r+w segment
		phcount++;
	}
	if (tls_size != 0) {
		phcount++;
		real_phcount++;
	}
	size_t eh_frame_size = 0;
	size_t eh_frame_hdr_size = 0;
	if (last_set_eh_frame_index != -1) {
		eh_frame_hdr_size = sizeof(struct eh_frame_hdr) + 2 * sizeof(int32_t) + eh_frame_count * sizeof(int32_t) * 2;
		// calculate the eh_frame size
		for (ssize_t i = 0; i < last_set_eh_frame_index; i++) {
			eh_frame_size += eh_frame_sizes[i].unterminated_size;
		}
		eh_frame_size += eh_frame_sizes[last_set_eh_frame_index].full_size;
	}
	rela_size += ((preinit_array_size + init_array_size + fini_array_size) * sizeof(ElfW(Rela))) / sizeof(ElfW(Addr));
	size_t phsize = phcount * sizeof(ElfW(Phdr));
	size_t symbol_size = symbol_count * sizeof(ElfW(Sym));
	size_t versym_size = versioning_binary != NULL ? symbol_count * sizeof(ElfW(Half)) : 0;
	if (eh_frame_size) {
		used_section_count++;
	}
	if (eh_frame_hdr_size) {
		used_section_count++;
	}
	size_t sections_size = used_section_count * sizeof(ElfW(Shdr));
	// calculate start of various new dynamic tags
	size_t symbol_start = ALIGN_UP(bootstrap != NULL ? phsize + (real_phcount + 10) * sizeof(ElfW(Phdr)) : phsize * 2, alignof(ElfW(Sym)));
	size_t versym_start = ALIGN_UP(symbol_start + symbol_size, sizeof(uint16_t));
	size_t string_start = versym_start + versym_size;
	size_t hash_start = ALIGN_UP(string_start + string_size, alignof(uint32_t));
	size_t rela_start = ALIGN_UP(hash_start + hash_size, alignof(ElfW(Rela)));
	size_t jmprel_start = ALIGN_UP(rela_start + rela_size, alignof(ElfW(Rela)));
	size_t eh_frame_hdr_start = ALIGN_UP(jmprel_start + jmprel_size, alignof(ElfW(Addr)));
	size_t eh_frame_start = ALIGN_UP(eh_frame_hdr_start + eh_frame_hdr_size, alignof(ElfW(Addr)));
	size_t tls_start = tls_size != 0 ? ALIGN_UP(eh_frame_start + eh_frame_size, tls_alignment) : eh_frame_start + eh_frame_size;
	size_t preinit_array_start = ALIGN_UP(tls_start + tls_size, PAGE_SIZE);
	size_t init_array_start = ALIGN_UP(preinit_array_start + preinit_array_size, alignof(ElfW(Addr)));
	size_t fini_array_start = ALIGN_UP(init_array_start + init_array_size, alignof(ElfW(Addr)));
	size_t sections_start = ALIGN_UP(fini_array_start + fini_array_size, PAGE_SIZE);
	size_t shstrtab_start = sections_start + sections_size;
	size_t extra_dynamic_size = fini_array_start + fini_array_size;
	size_t total_size = size + shstrtab_start + shstrtab_size;
	// open a file for the combined binary
	const char *path = main->path;
	const char *slash = fs_strrchr(path, '/');
	int copy = fs_open(slash != NULL ? slash + 1 : path, O_RDWR|O_CREAT|O_TRUNC, 0755);
	if (copy < 0) {
		DIE("failed open");
	}
	intptr_t result = fs_ftruncate(copy, total_size);
	if (result < 0) {
		result = fs_lseek(copy, total_size - 1, SEEK_SET);
		if (result < 0) {
			DIE("failed lseek");
		}
		char zero = 0;
		fs_write(copy, &zero, 1);
	}
	// map the empty binary
	void *mapping = fs_mmap(NULL, total_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FILE, copy, 0);
	if (fs_is_map_failed(mapping)) {
		DIE("failed mmap");
	}
	// copy the main binary's section strings
	char *shstrs = mapping + size + shstrtab_start;
	if (main->has_sections) {
		memcpy(shstrs, main->sections.strings, main_binary_section_string_size);
		shstrs += main_binary_section_string_size;
	}
	// copy the original binaries in, and merge the metadata
	size_t offset = 0;
	size_t address_offset = 0;
	ElfW(Phdr) *phdr = mapping + size;
	ElfW(Phdr) *real_phdr = mapping + size + phsize;
	struct symbol_ordering *symbol_ordering = malloc(symbol_count * sizeof(*symbol_ordering));
	symbol_ordering[0] = (struct symbol_ordering){0};
	size_t symbol_index = 1;
	char *strings = mapping + size + string_start;
	size_t strings_offset = 0;
	ElfW(Addr) soname = 0;
	size_t version_string_offset = 0;
	size_t dynamic_offset = 0;
	size_t tls_offset = 0;
	for (struct loaded_binary *binary = main; binary != NULL; binary = binary->previous) {
		if (should_include_binary(binary)) {
			// read the original binary
			int original = fs_open(binary->loaded_path, O_RDONLY, 0);
			if (original < 0) {
				DIE("failed reading original binary", binary->loaded_path);
			}
			result = fs_read_all(original, mapping + offset, binary->size);
			if (result < binary->size) {
				if (result < 0) {
					DIE("failed read", fs_strerror(result));
				}
				DIE("short read", result);
			}
			fs_close(original);
			// copy phdrs, fixing up the addresses
			ElfW(Addr) largest_addr = 0;
			const ElfW(Phdr) *old_phdr = binary->info.program_header;
			size_t binary_tls_size = 0;
			for (ElfW(Word) i = 0; i < binary->info.header_entry_count; i++) {
				switch (old_phdr[i].p_type) {
					case PT_LOAD: {
						ElfW(Addr) end = old_phdr[i].p_vaddr + old_phdr[i].p_memsz;
						if (end > largest_addr) {
							largest_addr = end;
						}
						break;
					}
					case PT_TLS: {
						tls_offset = ALIGN_UP(tls_offset, old_phdr[i].p_align) + old_phdr[i].p_memsz;
						binary_tls_size = old_phdr[i].p_memsz;
						break;
					}
				}
				if (should_include_program_header(binary, &old_phdr[i])) {
					switch (old_phdr[i].p_type) {
						case PT_PHDR:
							// include a program headers
							*phdr++ = (ElfW(Phdr)) {
								.p_type = PT_PHDR,
								.p_offset = size,
								.p_vaddr = address_size,
								.p_paddr = address_size,
								.p_memsz = phsize,
								.p_flags = PF_R,
								.p_align = alignof(ElfW(Phdr)),
							};
							if (bootstrap != NULL) {
								*real_phdr++ = (ElfW(Phdr)) {
									.p_type = PT_PHDR,
									.p_offset = size + phsize,
									.p_vaddr = address_size + phsize,
									.p_paddr = address_size + phsize,
									.p_memsz = real_phcount + sizeof(ElfW(Phdr)),
									.p_flags = PF_R,
									.p_align = alignof(ElfW(Phdr)),
								};
							}
							break;
						case PT_INTERP:
							// only copy interpreter into the embedded "real" program headers
							// that the interpreter sees, so the interpreter can find itself
							if (bootstrap != NULL) {
								*real_phdr++ = old_phdr[i];
							} else {
								*phdr++ = old_phdr[i];
							}
							break;
						case PT_DYNAMIC:
							// read the dynamic offset, so we can overwrite the dynamic headers
							if (binary == main) {
								dynamic_offset = old_phdr[i].p_offset;
							}
						default:
							// copy the program header and fixup its offsets/addresses
							*phdr = old_phdr[i];
							phdr->p_offset += offset;
							phdr->p_vaddr += address_offset;
							phdr->p_paddr += address_offset;
							if (bootstrap != NULL && binary != bootstrap) {
								*real_phdr++ = *phdr;
							}
							if (should_preserve_headers_for_binary(binary, bootstrap)) {
								phdr++;
							}
							break;
					}
				}
			}
			// record versioning strings offset
			if (binary == versioning_binary) {
				version_string_offset = strings_offset;
			}
			// import soname so that glibc can find itself
			if (binary->special_binary_flags & (BINARY_IS_LIBC|BINARY_IS_MAIN)) {
				const ElfW(Dyn) *dynamic = binary->info.dynamic;
				for (size_t i = 0; i < binary->info.dynamic_size; i++) {
					switch (dynamic[i].d_tag) {
						case DT_SONAME:
							soname = strings_offset + dynamic[i].d_un.d_val;
							break;
					}
				}
			}
			// prepare symbols for sorting and copy strings
			if (binary->has_symbols && binary != bootstrap && binary != interpreter) {
				// prepare symbols for ordering
				size_t stride = binary->symbols.symbol_stride;
				for (size_t i = 1, offset = stride; i < binary->symbols.symbol_count; i++, offset += stride, symbol_index++) {
					const ElfW(Sym) *orig_sym = (void *)binary->symbols.symbols + offset;
					symbol_ordering[symbol_index] = (struct symbol_ordering) {
						.source_index = i,
						.binary = binary,
						.gnu_hash = gnu_hash(&binary->symbols.strings[orig_sym->st_name]),
						.address_offset = address_offset,
						.strings_offset = strings_offset,
						.tls_offset = tls_offset,
					};
				}
				// copy the strings
				fs_memcpy(&strings[strings_offset], binary->symbols.strings, binary->symbols.strings_size);
				strings_offset += binary->symbols.strings_size;
			}
			offset += ALIGN_UP(binary->size, PAGE_SIZE);
			address_offset += ALIGN_UP(largest_addr, EXECUTABLE_BASE_ALIGN);
			tls_offset += binary_tls_size;
		}
	}
	// sort by class and then gnu hash
	qsort_r_freestanding(&symbol_ordering[1], symbol_count - 1, sizeof(*symbol_ordering), compare_symbol_ordering, NULL);
	size_t first_defined = 1;
	for (; first_defined < symbol_count; first_defined++) {
		if (ordering_class_for_sym(symbol_for_ordering_entry(&symbol_ordering[first_defined])) == ORDERING_CLASS_DEFINED) {
			break;
		}
	}
	// write out gnu hash table
	uint32_t *gnu_hash = mapping + size + hash_start;
	gnu_hash[0] = 1; // nbuckets
	gnu_hash[1] = first_defined; // symoffset
	gnu_hash[2] = 1; // bloom_size
	gnu_hash[3] = 0; // bloom_shift
	gnu_hash[4] = gnu_hash[5] = ~(uint32_t)0; // bloom; TODO: fill in bloom filter
	gnu_hash[6] = first_defined; // bucket; TODO: choose a better number of buckets
	gnu_hash += 7;
	for (size_t i = first_defined; i < symbol_count; i++) {
		*gnu_hash++ = symbol_ordering[i].gnu_hash & ~(uint32_t)1;
	}
	gnu_hash[-1] |= 1;
	// write out symbols
	ElfW(Sym) *symbols = mapping + size + symbol_start;
	ElfW(Half) *versym = mapping + size + versym_start;
	for (size_t i = 1; i < symbol_count; i++) {
		const ElfW(Sym) *orig_sym = symbol_for_ordering_entry(&symbol_ordering[i]);
		symbols[i] = (ElfW(Sym)) {
			.st_name = orig_sym->st_name == 0 ? 0 : orig_sym->st_name + symbol_ordering[i].strings_offset,
			.st_info = orig_sym->st_info,
			.st_other = orig_sym->st_other,
			.st_shndx = orig_sym->st_shndx,
			.st_value = orig_sym->st_value == 0 ? 0 : orig_sym->st_value + (ELF64_ST_TYPE(orig_sym->st_info) == STT_TLS ? symbol_ordering[i].tls_offset : symbol_ordering[i].address_offset),
			.st_size = orig_sym->st_size,
		};
		if (versioning_binary) {
			if (symbol_ordering[i].binary == versioning_binary) {
				versym[i] = symbol_ordering[i].binary->symbols.symbol_versions[symbol_ordering[i].source_index];
			} else {
				versym[i] = VER_NDX_LOCAL;
			}
		}
	}
	// calculate section mappings
	ElfW(Half) *section_mappings = malloc(section_count * sizeof(*section_mappings));
	size_t mapping_count = 0;
	size_t mapping_write_index = 0;
	for (struct loaded_binary *binary = main; binary != NULL; binary = binary->previous) {
		if (should_include_binary(binary)) {
			const ElfW(Shdr) *section = binary->sections.sections;
			for (size_t i = 0; i < binary->info.section_entry_count; i++) {
				section_mappings[mapping_write_index++] = mapping_count;
				mapping_count += should_include_section(binary, section);
				section = (void *)section + binary->info.section_entry_size;
			}
		}
	}
	// write out new rela, jumprel, initializers and finalizers
	ElfW(Ehdr) *header = mapping;
	ElfW(Rela) *relas = mapping + size + rela_start;
	ElfW(Rela) *jmprels = mapping + size + jmprel_start;
	ElfW(Addr) *preinit_array = mapping + size + preinit_array_start;
	ElfW(Addr) *init_array = mapping + size + init_array_start;
	ElfW(Addr) *fini_array = mapping + size + fini_array_start;
	ElfW(Shdr) *shdrs = mapping + size + sections_start;
	void *ehframe = mapping + size + eh_frame_start;
	size_t ehframe_offset = 0;
	address_offset = 0;
	offset = 0;
	size_t preinit_offset = 0;
	size_t init_offset = 0;
	size_t fini_offset = 0;
	size_t shdr_index = 0;
	size_t shdr_read_index = 0;
	size_t eh_frame_str_index = 0;
	size_t eh_frame_hdr_str_index = 0;
	int32_t *eh_frame_table = NULL;
	if (eh_frame_hdr_size) {
		// write eh_frame
		struct eh_frame_hdr *hdr = mapping + size + eh_frame_hdr_start;
		*hdr = (struct eh_frame_hdr) {
			.version = 1,
			.eh_frame_ptr_enc =  (DW_EH_PE_pcrel | DW_EH_PE_sdata4),
			.fde_count_enc = DW_EH_PE_udata4,
			.table_enc = (DW_EH_PE_datarel | DW_EH_PE_sdata4),
		};
		eh_frame_table = (int32_t *)&hdr->data[0];
		*eh_frame_table++ = eh_frame_start - (eh_frame_hdr_start + sizeof(struct eh_frame_hdr));
		*eh_frame_table++ = eh_frame_count;
	}
	binary_index = 0;
	tls_offset = 0;
	for (struct loaded_binary *binary = main; binary != NULL; binary = binary->previous) {
		if (should_include_binary(binary)) {
			// copy eh frames, loaded segments, and merge TLS
			ElfW(Addr) largest_addr = 0;
			ElfW(Addr) binary_tls_address = 0;
			size_t binary_tls_size = 0;
			size_t binary_defined_size = 0;
			const ElfW(Phdr) *phdr = binary->info.program_header;
			for (ElfW(Word) i = 0; i < binary->info.header_entry_count; i++) {
				switch (phdr[i].p_type) {
					case PT_GNU_EH_FRAME: {
						size_t size = binary_index == last_set_eh_frame_index ? eh_frame_sizes[binary_index].full_size : eh_frame_sizes[binary_index].unterminated_size;
						memcpy(ehframe + ehframe_offset, binary->frame_info.data, size);
						size_t eh_frame_vaddr = binary->frame_info.data - binary->info.base;
						size_t pc_offset_diff = eh_frame_vaddr + address_offset - (address_size + eh_frame_start + ehframe_offset);
						size_t binary_table_pc_offset_diff = eh_frame_vaddr + address_offset - (eh_frame_hdr_start + address_size);
						size_t binary_table_fde_offset_diff = eh_frame_start + ehframe_offset - eh_frame_hdr_start;
						patch_eh_frames(ehframe + ehframe_offset, pc_offset_diff, eh_frame_table, binary_table_pc_offset_diff, binary_table_fde_offset_diff);
						eh_frame_table += eh_frame_sizes[binary_index].count;
						ehframe_offset += size;
						break;
					}
					case PT_LOAD: {
						ElfW(Addr) end = phdr[i].p_vaddr + phdr[i].p_memsz;
						if (end > largest_addr) {
							largest_addr = end;
						}
						break;
					}
					case PT_TLS: {
						binary_tls_address = phdr[i].p_vaddr;
						binary_tls_size = phdr[i].p_memsz;
						binary_defined_size = phdr[i].p_filesz;
						tls_offset = ALIGN_UP(tls_offset, phdr[i].p_align);
						memcpy(mapping + size + tls_start + tls_offset, mapping + offset + phdr[i].p_offset, phdr[i].p_filesz);
						break;
					}
				}
			}
			// copy relocations, initializers, and finalizers
			if (binary != bootstrap && binary != interpreter) {
				const ElfW(Dyn) *dynamic = binary->info.dynamic;
				uintptr_t rela = 0;
				size_t relasz = 0;
				size_t relaent = 0;
				uintptr_t jmprel = 0;
				uintptr_t pltrelsz = 0;
				uintptr_t preinitarray = 0;
				size_t preinitarraysz = 0;
				uintptr_t init = 0;
				uintptr_t initarray = 0;
				size_t initarraysz = 0;
				uintptr_t fini = 0;
				uintptr_t finiarray = 0;
				size_t finiarraysz = 0;
				for (size_t i = 0; i < binary->info.dynamic_size; i++) {
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
						case DT_JMPREL:
							jmprel = dynamic[i].d_un.d_ptr;
							break;
						case DT_PLTRELSZ:
							pltrelsz = dynamic[i].d_un.d_val;
							break;
						case DT_PREINIT_ARRAY:
							preinitarray = dynamic[i].d_un.d_ptr;
							break;
						case DT_PREINIT_ARRAYSZ:
							preinitarraysz = dynamic[i].d_un.d_val;
							break;
						case DT_INIT:
							init = dynamic[i].d_un.d_ptr;
							break;
						case DT_INIT_ARRAY:
							initarray = dynamic[i].d_un.d_ptr;
							break;
						case DT_INIT_ARRAYSZ:
							initarraysz = dynamic[i].d_un.d_val;
							break;
						case DT_FINI:
							fini = dynamic[i].d_un.d_ptr;
							break;
						case DT_FINI_ARRAY:
							finiarray = dynamic[i].d_un.d_ptr;
							break;
						case DT_FINI_ARRAYSZ:
							finiarraysz = dynamic[i].d_un.d_val;
							break;
					}
				}
				ssize_t tls_address_offset = address_size + tls_start + tls_offset - binary_tls_address;
				// copy and fixup relas
				copy_relas(binary, &relas, rela, relasz, relaent, address_offset, binary_tls_address, binary_defined_size, tls_address_offset, tls_offset, symbol_ordering, symbol_count);
				// copy and fixup jmprels
				copy_relas(binary, &jmprels, jmprel, pltrelsz, relaent, address_offset, binary_tls_address, binary_defined_size, tls_address_offset, tls_offset, symbol_ordering, symbol_count);
				// copy preinit array
				for (size_t i = 0; i < preinitarraysz; i += sizeof(uintptr_t)) {
					ElfW(Addr) addr = *(const ElfW(Addr) *)(mapping + offset + file_offset_for_binary_address(binary, preinitarray + i)) + address_offset;
					add_init_function(preinit_array, &preinit_offset, &relas, address_size + preinit_array_start, addr);
				}
				// copy init array
				if (init) {
					add_init_function(init_array, &init_offset, &relas, address_size + init_array_start, init + address_offset);
				}
				for (size_t i = 0; i < initarraysz; i += sizeof(uintptr_t)) {
					ElfW(Addr) addr = *(const ElfW(Addr) *)(mapping + offset + file_offset_for_binary_address(binary, initarray + i)) + address_offset;
					add_init_function(init_array, &init_offset, &relas, address_size + init_array_start, addr);
				}
				// copy fini array
				if (fini) {
					add_init_function(fini_array, &fini_offset, &relas, address_size + fini_array_start, fini + address_offset);
				}
				for (size_t i = 0; i < finiarraysz; i += sizeof(uintptr_t)) {
					ElfW(Addr) addr = *(const ElfW(Addr) *)(mapping + offset + file_offset_for_binary_address(binary, finiarray + i)) + address_offset;
					add_init_function(fini_array, &fini_offset, &relas, address_size + fini_array_start, addr);
				}
			}
			// copy sections
			const ElfW(Shdr) *section = binary->sections.sections;
			for (size_t i = 0; i < binary->info.section_entry_count; i++) {
				const char *name = &binary->sections.strings[section->sh_name];
				if (section->sh_type == SHT_PROGBITS && binary == main) {
					if (fs_strcmp(name, ".eh_frame") == 0) {
						eh_frame_str_index = section->sh_name;
					} else if (fs_strcmp(name, ".eh_frame_hdr") == 0) {
						eh_frame_hdr_str_index = section->sh_name;
					}
				}
				if (should_include_section(binary, section)) {
					shdrs[shdr_index] = *section;
					shdrs[shdr_index].sh_offset += offset;
					if (section->sh_flags & SHF_ALLOC) {
						shdrs[shdr_index].sh_addr += address_offset;
					}
					if (binary != main) {
						shdrs[shdr_index].sh_name = shstrs - (char *)(mapping + size + shstrtab_start);
						shstrs = fs_strcpy(shstrs, name);
						*shstrs++ = '.';
						shstrs = fs_strcpy(shstrs, binary->path) + 1;
					}
					shdrs[shdr_index].sh_link = section_mappings[shdr_read_index + shdrs[shdr_index].sh_link];
					if (binary == main) {
						switch (section->sh_type) {
							case SHT_STRTAB:
								if (fs_strcmp(name, ".dynstr") == 0) {
									shdrs[shdr_index].sh_offset = size + string_start;
									shdrs[shdr_index].sh_addr = address_size + string_start;
									shdrs[shdr_index].sh_size = string_size;
								}
								if (fs_strcmp(name, ".shstrtab") == 0 && binary == main) {
									shdrs[shdr_index].sh_offset = size + shstrtab_start;
									shdrs[shdr_index].sh_size = shstrtab_size;
								}
								break;
							case SHT_DYNSYM:
								if (fs_strcmp(name, ".dynsym") == 0) {
									shdrs[shdr_index].sh_offset = size + symbol_start;
									shdrs[shdr_index].sh_addr = address_size + symbol_start;
									shdrs[shdr_index].sh_size = symbol_size;
									shdrs[shdr_index].sh_entsize = sizeof(ElfW(Sym));
								}
								break;
							case SHT_GNU_HASH:
								if (fs_strcmp(name, ".gnu.hash") == 0) {
									shdrs[shdr_index].sh_offset = size + hash_start;
									shdrs[shdr_index].sh_addr = address_size + hash_start;
									shdrs[shdr_index].sh_size = hash_size;
								}
								break;
							case SHT_RELA:
								if (fs_strcmp(name, ".rela.dyn") == 0) {
									shdrs[shdr_index].sh_offset = size + rela_start;
									shdrs[shdr_index].sh_addr = address_size + rela_start;
									shdrs[shdr_index].sh_size = rela_size;
									shdrs[shdr_index].sh_entsize = sizeof(ElfW(Rela));
								}
								if (fs_strcmp(name, ".rela.plt") == 0) {
									shdrs[shdr_index].sh_offset = size + jmprel_start;
									shdrs[shdr_index].sh_addr = address_size + jmprel_start;
									shdrs[shdr_index].sh_size = jmprel_size;
									shdrs[shdr_index].sh_entsize = sizeof(ElfW(Rela));
								}
								shdrs[shdr_index].sh_info = section_mappings[shdr_read_index + shdrs[shdr_index].sh_info];
								break;
							case SHT_GNU_versym:
								if (fs_strcmp(name, ".gnu.version") == 0) {
									shdrs[shdr_index].sh_offset = size + versym_start;
									shdrs[shdr_index].sh_addr = address_size + versym_start;
									shdrs[shdr_index].sh_size = versym_size;
								}
								break;
						}
					} else {
						if (shdrs[shdr_index].sh_type != SHT_NOBITS) {
							shdrs[shdr_index].sh_type = SHT_PROGBITS;
						}
						shdrs[shdr_index].sh_info = 0;
					}
					shdr_index++;
				}
				section = (void *)section + binary->info.section_entry_size;
			}
			shdr_read_index += binary->info.section_entry_count;
			address_offset += ALIGN_UP(largest_addr, EXECUTABLE_BASE_ALIGN);
			offset += ALIGN_UP(binary->size, PAGE_SIZE);
			tls_offset += binary_tls_size;
			binary_index++;
		}
	}
	// declare frame headers
	if (eh_frame_hdr_size) {
		shdrs[shdr_index++] = (ElfW(Shdr)) {
			.sh_name = eh_frame_hdr_str_index,
			.sh_type = SHT_PROGBITS,
			.sh_flags = SHF_ALLOC,
			.sh_addr = address_size + eh_frame_hdr_start,
			.sh_offset = size + eh_frame_hdr_start,
			.sh_size = eh_frame_hdr_size,
			.sh_link = 0,
			.sh_info = 0,
			.sh_addralign = alignof(struct eh_frame_hdr),
			.sh_entsize = 0,
		};
	}
	if (eh_frame_size) {
		shdrs[shdr_index++] = (ElfW(Shdr)) {
			.sh_name = eh_frame_str_index,
			.sh_type = SHT_PROGBITS,
			.sh_flags = SHF_ALLOC,
			.sh_addr = address_size + eh_frame_start,
			.sh_offset = size + eh_frame_start,
			.sh_size = eh_frame_size,
			.sh_link = 0,
			.sh_info = 0,
			.sh_addralign = alignof(ElfW(Addr)),
			.sh_entsize = 0,
		};
	}
	if (shdr_index != used_section_count) {
		ERROR("written section count", (intptr_t)shdr_index);
		DIE("does not match expected count", (intptr_t)used_section_count);
	}
	// add a read-only mapping for the relocated structures
	*real_phdr++ = *phdr++ = (ElfW(Phdr)) {
		.p_type = PT_LOAD,
		.p_flags = PF_R,
		.p_offset = size,
		.p_vaddr = address_size,
		.p_paddr = address_size,
		.p_filesz = tls_start,
		.p_memsz = tls_start,
		.p_align = PAGE_SIZE,
	};
	// and a read/write mapping for the init/fini arrays
	if (preinit_array_size | init_array_size | fini_array_size) {
		*real_phdr++ = *phdr++ = (ElfW(Phdr)) {
			.p_type = PT_LOAD,
			.p_flags = PF_R|PF_W,
			.p_offset = size + tls_start,
			.p_vaddr = address_size + tls_start,
			.p_paddr = address_size + tls_start,
			.p_filesz = extra_dynamic_size - tls_start,
			.p_memsz = extra_dynamic_size - tls_start,
			.p_align = PAGE_SIZE,
		};
	}
	// add a TLS declaration
	if (tls_size != 0) {
		if (bootstrap != NULL) {
			*phdr++ = *real_phdr++ = (ElfW(Phdr)) {
				.p_type = PT_TLS,
				.p_flags = PF_R,
				.p_offset = size + tls_start,
				.p_vaddr = address_size + tls_start,
				.p_paddr = address_size + tls_start,
				.p_filesz = tls_size,
				.p_memsz = tls_size,
				.p_align = tls_alignment,
			};
		} else {
			*phdr++ = (ElfW(Phdr)) {
				.p_type = PT_TLS,
				.p_flags = PF_R,
				.p_offset = size + tls_start,
				.p_vaddr = address_size + tls_start,
				.p_paddr = address_size + tls_start,
				.p_filesz = tls_size,
				.p_memsz = tls_size,
				.p_align = tls_alignment,
			};
		}
	}
	// patch dynamic entries
	// TODO: relocate dynamic entries to the end of the address space
	ElfW(Dyn) *dyn = mapping + dynamic_offset;
	const ElfW(Dyn) *orig_dyn = dyn;
	do {
		*dyn = *orig_dyn++;
		switch (dyn->d_tag) {
			case DT_NEEDED: {
				const char *needed_path = main->symbols.strings + dyn->d_un.d_val;
				struct loaded_binary *binary = find_loaded_binary(&analysis->loader, needed_path);
				if (binary != NULL && should_include_binary(binary) && (binary->special_binary_flags & BINARY_IS_INTERPRETER) == 0) {
					continue;
				}
				break;
			}
			case DT_GNU_HASH:
				dyn->d_un.d_ptr = address_size + hash_start;
				break;
			case DT_SYMTAB:
				dyn->d_un.d_ptr = address_size + symbol_start;
				break;
			case DT_STRTAB:
				dyn->d_un.d_ptr = address_size + string_start;
				break;
			case DT_STRSZ:
				dyn->d_un.d_val = string_size;
				break;
			case DT_SYMENT:
				dyn->d_un.d_val = sizeof(ElfW(Sym));
				break;
			case DT_RELA:
				dyn->d_un.d_ptr = address_size + rela_start;
				break;
			case DT_RELASZ:
				dyn->d_un.d_val = rela_size;
				break;
			case DT_RELAENT:
				dyn->d_un.d_val = sizeof(ElfW(Rela));
				break;
			case DT_RELACOUNT:
				// relative relocations are not necessarily in a single block
				continue;
			case DT_JMPREL:
				dyn->d_un.d_ptr = address_size + jmprel_start;
				break;
			case DT_PLTRELSZ:
				dyn->d_un.d_val = jmprel_size;
				break;
			case DT_INIT_ARRAY:
				dyn->d_un.d_ptr = address_size + init_array_start;
				break;
			case DT_INIT_ARRAYSZ:
				dyn->d_un.d_val = init_array_size;
				break;
			case DT_FINI_ARRAY:
				dyn->d_un.d_ptr = address_size + fini_array_start;
				break;
			case DT_FINI_ARRAYSZ:
				dyn->d_un.d_val = fini_array_size;
				break;
			case DT_INIT:
			case DT_FINI:
			case DT_SONAME:
				// these tags are replaced entirely
				continue;
			case DT_VERSYM:
			case DT_VERDEF:
			case DT_VERDEFNUM:
			case DT_VERNEED:
			case DT_VERNEEDNUM:
				// TODO: support symbol versioning
				continue;
		}
		dyn++;
	} while(orig_dyn->d_tag != DT_NULL);
	// add the soname that way glibc can find itself
	if (soname != 0) {
		dyn->d_tag = DT_SONAME;
		dyn->d_un.d_val = soname;
		dyn++;
	}
	// patch in versioning information
	if (versioning_binary != NULL) {
		dyn->d_tag = DT_VERSYM;
		dyn->d_un.d_ptr = address_size + versym_start;
		dyn++;
		address_offset = address_for_binary(&analysis->loader, versioning_binary);
		size_t libc_file_offset = file_offset_for_binary(&analysis->loader, versioning_binary);
		if (verdef != 0 && verdefnum != 0) {
			dyn->d_tag = DT_VERDEF;
			dyn->d_un.d_ptr = address_offset + verdef;
			dyn++;
			dyn->d_tag = DT_VERDEFNUM;
			dyn->d_un.d_val = verdefnum;
			dyn++;
			ElfW(Verdef) *vd = mapping + libc_file_offset + file_offset_for_binary_address(versioning_binary, verdef);
			for (;;) {
				if (vd->vd_version != 1) {
					break;
				}
				ElfW(Verdaux) *aux = (void *)vd + vd->vd_aux;
				for (size_t i = 0; i < vd->vd_cnt; i++) {
					aux->vda_name += version_string_offset;
					aux = (void *)aux + aux->vda_next;
				}
				if (vd->vd_next == 0) {
					break;
				}
				vd = (void *)vd + vd->vd_next;
			}
		}
		if (verneed != 0 && verneednum != 0) {
			dyn->d_tag = DT_VERNEED;
			dyn->d_un.d_ptr = address_offset + verneed;
			dyn++;
			dyn->d_tag = DT_VERNEEDNUM;
			dyn->d_un.d_val = verneednum;
			dyn++;
			ElfW(Verneed) *vn = mapping + libc_file_offset + file_offset_for_binary_address(versioning_binary, verneed);
			for (;;) {
				if (vn->vn_version != 1) {
					break;
				}
				vn->vn_file += version_string_offset;
				ElfW(Vernaux) *aux = (void *)vn + vn->vn_aux;
				for (size_t i = 0; i < vn->vn_cnt; i++) {
					aux->vna_name += version_string_offset;
					aux = (void *)aux + aux->vna_next;
				}
				if (vn->vn_next == 0) {
					break;
				}
				vn = (void *)vn + vn->vn_next;
			}
		}
	}
	dyn->d_tag = DT_NULL;
	dyn->d_un.d_val = 0;
	// commit changes to the ELF header
#if 0
	header->e_phoff = size + phsize;
	header->e_phnum = real_phcount;
#else
	header->e_phoff = size;
	header->e_phnum = phcount;
#endif
	header->e_shoff = size + sections_start;
	header->e_shnum = used_section_count;
	header->e_shentsize = sizeof(ElfW(Shdr));
	header->e_shstrndx = section_mappings[header->e_shstrndx];
	if (bootstrap != NULL) {
		// bake bootstrap offsets into the binary
		struct bootstrap_offsets *offsets = mapping + file_offset_for_binary(&analysis->loader, bootstrap) + file_offset_for_binary_address(bootstrap, offset_for_self_symbol(&bootstrap->info, &bootstrap_offsets));
		offsets->base_to_bootstrap_dynamic = address_for_binary(&analysis->loader, bootstrap) + offset_for_self_symbol(&bootstrap->info, &_DYNAMIC);
		offsets->interpreter_base = address_for_binary(&analysis->loader, interpreter);
		offsets->main_entrypoint = (uintptr_t)main->info.entrypoint - (uintptr_t)main->info.base;
		offsets->real_program_header = address_size + phsize;
		offsets->header = *header;
		offsets->header.e_phoff = size + phsize;
		offsets->header.e_phentsize = sizeof(ElfW(Phdr));
		offsets->header.e_phnum = real_phcount;
		offsets->remap_binary = remap_binary;
#if PRINT_GDB_COMMANDS
		binary_index = 0;
		address_offset = 0;
		for (struct loaded_binary *binary = main; binary != NULL; binary = binary->previous) {
			if (should_include_binary(binary)) {
				ElfW(Addr) largest_addr = 0;
				const ElfW(Phdr) *phdr = binary->info.program_header;
				for (ElfW(Word) i = 0; i < binary->info.header_entry_count; i++) {
					switch (phdr[i].p_type) {
						case PT_LOAD: {
							ElfW(Addr) end = phdr[i].p_vaddr + phdr[i].p_memsz;
							if (end > largest_addr) {
								largest_addr = end;
							}
							break;
						}
					}
				}
				if (binary->has_sections) {
					const ElfW(Shdr) *shdr = find_section(&binary->info, &binary->sections, ".text");
					if (shdr != NULL) {
						size_t name_len = fs_strlen(binary->loaded_path) + 1;
						fs_memcpy(&strings[strings_offset], binary->loaded_path, name_len);
						offsets->embedded_binaries[binary_index] = (struct embedded_binary) {
							.name = address_size + string_start + strings_offset,
							.text_address = address_offset + shdr->sh_addr,
						};
						strings_offset += name_len;
					}
				}
				binary_index++;
				address_offset += ALIGN_UP(largest_addr, EXECUTABLE_BASE_ALIGN);
			}
		}
#endif
		header->e_entry = address_for_binary(&analysis->loader, bootstrap) + offset_for_self_symbol(&bootstrap->info, bootstrap_trampoline);
	}
	// cleanup
	free(section_mappings);
	free(symbol_ordering);
	free(offsets);
	fs_close(copy);
}

#pragma GCC push_options
#pragma GCC optimize ("-fomit-frame-pointer")
__attribute__((noinline, visibility("hidden")))
int main(int argc, char* argv[], char* envp[])
{
	struct program_state analysis = {0};
	// Find PATH and LD_PRELOAD
	int envp_count = 0;
	const char *path = "/bin:/usr/bin";
	for (char **s = envp; *s != NULL; s++) {
		if (fs_strncmp(*s, "LD_PRELOAD=", sizeof("LD_PRELOAD=")-1) == 0) {
			analysis.ld_preload = *s + sizeof("LD_PRELOAD=")-1;
		} else {
			if (fs_strncmp(*s, "PATH=", sizeof("PATH=")-1) == 0) {
				const char *new_path = &(*s)[sizeof("PATH=")-1];
				if (*new_path != '\0') {
					path = new_path;
				}
			} else if (fs_strncmp(*s, "LD_PROFILE=", sizeof("LD_PROFILE=")-1) == 0) {
				const char *new_path = &(*s)[sizeof("LD_PROFILE=")-1];
				if (*new_path != '\0') {
					analysis.ld_profile = new_path;
				}
			}
			envp_count++;
		}
	}
	for (const ElfW(auxv_t) *aux = (const ElfW(auxv_t) *)(envp + envp_count + 1); aux->a_type != AT_NULL; aux++) {
		switch (aux->a_type) {
			case AT_EUID:
				analysis.loader.uid = aux->a_un.a_val;
				break;
			case AT_EGID:
				analysis.loader.gid = aux->a_un.a_val;
				break;
			case AT_SYSINFO_EHDR:
				analysis.loader.vdso = aux->a_un.a_val;
				break;
		}
	}
	int executable_index = 1;
	while (argv[executable_index] && *argv[executable_index] == '-') {
		const char *arg = argv[executable_index];
		if (fs_strcmp(arg, "--") == 0) {
			executable_index++;
			break;
		} else {
			ERROR("unknown command line option", arg);
			return 1;
		}
		executable_index++;
	}
	const char *executable_path = argv[executable_index];

	if (!executable_path) {
		ERROR_WRITE_LITERAL("usage: smoosh [binary]\n"\
		"Merges a program with its libraries\n"\
		"Copyright (C) 2020-2025 Ryan Petrich\n");
		return 1;
	}

	// open the main executable
	int fd = open_executable_in_paths(executable_path, path, true, analysis.loader.uid, analysis.loader.gid);
	if (UNLIKELY(fd < 0)) {
		ERROR("could not find main executable", executable_path);
		return 1;
	}

	// find path so we can open it later
	char path_buf[PATH_MAX];
	intptr_t result = fs_fd_getpath(fd, path_buf);
	if (result < 0) {
		DIE("failed to read path", fs_strerror(result));
	}

	init_searched_instructions(&analysis.search);

	// load the main executable
	struct loaded_binary *loaded;
	result = load_binary_into_analysis(&analysis, executable_path, executable_path, fd, NULL, &loaded);
	if (result != 0) {
		DIE("failed to load main binary", fs_strerror(result));
	}
	fs_close(fd);

	load_all_needed_and_relocate(&analysis);

	struct loaded_binary *bootstrap = NULL;

	// if bundling interpreter, add self to bootstrap
	if ((loaded->info.interpreter != NULL && bundle_interpreter) || remap_binary) {
		fd = fs_open("/proc/self/exe", O_RDONLY, 0);
		if (fd < 0) {
			DIE("failed to read self", fs_strerror(fd));
		}
		char buf[PATH_MAX];
		result = fs_fd_getpath(fd, buf);
		if (result < 0) {
			DIE("failed to read self path", fs_strerror(fd));
		}
		result = load_binary_into_analysis(&analysis, "bootstrap", buf, fd, NULL, &bootstrap);
		if (result != 0) {
			DIE("failed to load self", fs_strerror(result));
		}
		fs_close(fd);
	}

	write_combined_binary(&analysis, bootstrap);

	cleanup_searched_instructions(&analysis.search);
	free_loader_context(&analysis.loader);

	return 0;
}
#pragma GCC pop_options
