#define _GNU_SOURCE

#include "loader.h"
#include "axon.h"
#include "qsort.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>

#define INDEX_SYMBOLS

#define PAGE_ALIGNMENT_MASK ~((uintptr_t)PAGE_SIZE - 1)

#define DW_EH_PE_omit	0xff
#define DW_EH_PE_ptr	0x00

#define DW_EH_PE_uleb128	0x01
#define DW_EH_PE_udata2	0x02
#define DW_EH_PE_udata4	0x03
#define DW_EH_PE_udata8	0x04
#define DW_EH_PE_sleb128	0x09
#define DW_EH_PE_sdata2	0x0a
#define DW_EH_PE_sdata4	0x0b
#define DW_EH_PE_sdata8	0x0c
#define DW_EH_PE_signed	0x09

#define DW_EH_PE_absptr 0x00
#define DW_EH_PE_pcrel	0x10
#define DW_EH_PE_textrel	0x20
#define DW_EH_PE_datarel	0x30

static int protection_for_pflags(int pflags)
{
	int protection = 0;
	if (pflags & PF_R) {
		protection |= PROT_READ;
	}
	if (pflags & PF_W) {
		protection |= PROT_WRITE;
	}
	if (pflags & PF_X) {
		protection |= PROT_EXEC;
	}
	return protection;
}

// load_binary will load and map the binary in fd into the process' address space
int load_binary(int fd, struct binary_info *out_info, uintptr_t load_address, bool force_relocation)
{
	const ElfW(Ehdr) header;
	int read_bytes = fs_pread_all(fd, (char *)&header, sizeof(header), 0);
	if (read_bytes < 0) {
		ERROR("unable to read ELF header", fs_strerror(read_bytes));
		return -ENOEXEC;
	}
	if (read_bytes < (int)sizeof(ElfW(Ehdr))) {
		ERROR("too few bytes for ELF header", read_bytes);
		return -ENOEXEC;
	}
	if (header.e_ident[EI_MAG0] != ELFMAG0 || header.e_ident[EI_MAG1] != ELFMAG1 || header.e_ident[EI_MAG2] != ELFMAG2 || header.e_ident[EI_MAG3] != ELFMAG3) {
		ERROR("not an ELF binary");
		return -ENOEXEC;
	}
	if (header.e_ident[EI_CLASS] != CURRENT_CLASS) {
#ifdef __LP64__
		ERROR("ELF binary is not 64-bit");
#else
		ERROR("ELF binary is not 32-bit");
#endif
		return -ENOEXEC;
	}
	if (header.e_ident[EI_DATA] != ELFDATA2LSB) {
		ERROR("ELF binary is not little-endian");
		return -ENOEXEC;
	}
	if (header.e_ident[EI_VERSION] != EV_CURRENT) {
		ERROR("ELF identifier version is not current");
		return -ENOEXEC;
	}
	if (header.e_ident[EI_OSABI] != ELFOSABI_SYSV && header.e_ident[EI_OSABI] != ELFOSABI_LINUX) {
		ERROR("ELF binary ABI is not SYSV or Linux");
		return -ENOEXEC;
	}
	if (header.e_ident[EI_ABIVERSION] != 0) {
		ERROR("ELF binary has an unknown ABI version");
		return -ENOEXEC;
	}
	if (header.e_type != ET_EXEC && header.e_type != ET_DYN) {
		ERROR("ELF binary has unexpected type", (int)header.e_type);
		return -ENOEXEC;
	}
	if (header.e_machine != CURRENT_ELF_MACHINE) {
		ERROR("ELF binary has unexpected machine type", (int)header.e_machine);
		return -ENOEXEC;
	}
	if (header.e_version != EV_CURRENT) {
		ERROR("ELF binary version is not current", header.e_version);
		return -ENOEXEC;
	}
	struct fs_stat stat;
	int result = fs_fstat(fd, &stat);
	if (result < 0) {
		ERROR("could not stat binary", fs_strerror(result));
		return -ENOEXEC;
	}
	size_t phsize = header.e_phentsize * header.e_phnum;
	out_info->header_entry_size = header.e_phentsize;
	out_info->header_entry_count = header.e_phnum;
	char *phbuffer = malloc(phsize);
	out_info->phbuffer = phbuffer;
	int l = fs_pread_all(fd, phbuffer, phsize, header.e_phoff);
	if (l != (int)phsize) {
		free(phbuffer);
		if (l < 0) {
			ERROR("unable to read phbuffer", fs_strerror(l));
		} else {
			ERROR("read of phbuffer was the wrong size", l);
		}
		return -ENOEXEC;
	}
	uintptr_t start = UINTPTR_MAX;
	uintptr_t off_start = 0;
	uintptr_t end = 0;
	uintptr_t off_interpreter = 0;
	const ElfW(Phdr) *dynamic_ph = NULL;
	for (int i = 0; i < header.e_phnum; i++) {
		const ElfW(Phdr) *ph = (const ElfW(Phdr) *)&phbuffer[header.e_phentsize * i];
		switch (ph->p_type) {
			case PT_LOAD: {
				if ((uintptr_t)ph->p_vaddr <= start) {
					start = (uintptr_t)ph->p_vaddr;
					off_start = (uintptr_t)ph->p_offset;
				}
				if ((uintptr_t)ph->p_vaddr + (uintptr_t)ph->p_memsz > end) {
					end = (uintptr_t)ph->p_vaddr + (uintptr_t)ph->p_memsz;
				}
				break;
			}
			case PT_DYNAMIC: {
				dynamic_ph = ph;
				break;
			}
			case PT_INTERP: {
				off_interpreter = ph->p_offset;
				break;
			}
			case PT_GNU_STACK: {
				out_info->executable_stack = ph->p_flags & PF_X ? EXECUTABLE_STACK_REQUIRED : EXECUTABLE_STACK_PROHIBITED;
				break;
			}
		}
	}
	end += PAGE_SIZE-1;
	end &= PAGE_ALIGNMENT_MASK;
	off_start &= PAGE_ALIGNMENT_MASK;
	start &= PAGE_ALIGNMENT_MASK;
	size_t total_size = end - start + off_start;
	uintptr_t desired_address = load_address == 0 || header.e_type != ET_DYN ? start - off_start : load_address;
#ifdef MAP_JIT
	int additional_map_flags = MAP_JIT;
#else
	int additional_map_flags = 0;
#endif
	void *mapped_address = fs_mmap((void *)desired_address, total_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|additional_map_flags, -1, 0);
	if (fs_is_map_failed(mapped_address)) {
		ERROR("could not map binary", fs_strerror((intptr_t)mapped_address));
		free(phbuffer);
		return -ENOEXEC;
	}
	if ((uintptr_t)mapped_address != desired_address && header.e_type != ET_DYN && load_address == 0 && !force_relocation) {
		ERROR("desired address is not allowed", desired_address);
		ERROR("instead got", (uintptr_t)mapped_address);
		// ERROR("binary is not relocable");
		fs_munmap(mapped_address, end - start + off_start);
		free(phbuffer);
		return -ENOEXEC;
	}
	uintptr_t map_offset = (uintptr_t)mapped_address - start + off_start;
	for (int i = 0; i < header.e_phnum; i++) {
		const ElfW(Phdr) *ph = (const ElfW(Phdr) *)&phbuffer[header.e_phentsize * i];
		if (ph->p_type != PT_LOAD) {
			continue;
		}
		uintptr_t this_min = ph->p_vaddr & PAGE_ALIGNMENT_MASK;
		uintptr_t this_max = (ph->p_vaddr + ph->p_memsz + PAGE_SIZE-1) & PAGE_ALIGNMENT_MASK;
		int protection = protection_for_pflags(ph->p_flags);
		if (this_max-this_min) {
			size_t offset = ph->p_offset & PAGE_ALIGNMENT_MASK;
			size_t len = this_max-this_min;
			size_t map_len = len;
			if (offset + len > (size_t)stat.st_size) {
				map_len = (((size_t)stat.st_size - offset) + PAGE_SIZE-1) & PAGE_ALIGNMENT_MASK;
			}
			void *desired_section_mapping = (void *)(map_offset + this_min);
			int temporary_prot = ph->p_memsz > ph->p_filesz ? (protection | PROT_READ | PROT_WRITE) : protection;
			if (map_len != 0) {
#ifdef __APPLE__
				void *section_mapping = fs_mmap(desired_section_mapping, map_len, temporary_prot & ~PROT_EXEC, MAP_PRIVATE|MAP_FIXED, fd, offset);
#else
				void *section_mapping = fs_mmap(desired_section_mapping, map_len, temporary_prot, MAP_PRIVATE|MAP_FIXED, fd, offset);
#endif
				if (fs_is_map_failed(section_mapping)) {
					ERROR("failed mapping section", fs_strerror((intptr_t)section_mapping));
					return -ENOEXEC;
				}
				if (section_mapping != desired_section_mapping) {
					ERROR("section mapped to incorrect address", (uintptr_t)section_mapping);
					ERROR("expected", (uintptr_t)desired_section_mapping);
					return -ENOEXEC;
				}
#ifdef __APPLE__
				if (temporary_prot & PROT_EXEC) {
					result = fs_mprotect(desired_section_mapping, map_len, temporary_prot);
					if (result != 0) {
						ERROR("failed adding PROT_EXEC", fs_strerror(result));
						return -ENOEXEC;
					}
				}
#endif
			}
		}
		if (ph->p_memsz > ph->p_filesz) {
			size_t brk = (size_t)map_offset+ph->p_vaddr+ph->p_filesz;
			size_t pgbrk = (brk+PAGE_SIZE-1) & PAGE_ALIGNMENT_MASK;
			memset((void *)brk, 0, (pgbrk-brk) & (PAGE_SIZE-1));
			if (this_max-this_min && protection != (protection | PROT_READ | PROT_WRITE)) {
				result = fs_mprotect((void *)(map_offset + this_min), this_max-this_min, protection);
				if (result < 0) {
					ERROR("failed remapping section with new protection", fs_strerror(result));
					return -ENOEXEC;
				}
			}
			if (pgbrk-(size_t)map_offset < this_max) {
				void *tail_mapping = fs_mmap((void *)pgbrk, (size_t)map_offset+this_max-pgbrk, protection, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
				if (fs_is_map_failed(tail_mapping)) {
					ERROR("failed creating .bss-like PT_LOAD", fs_strerror((intptr_t)tail_mapping));
					return -ENOEXEC;
				}
			}
		}
	}

	out_info->base = mapped_address;
	out_info->default_base = (void *)(start - off_start);
	out_info->size = total_size;
	out_info->program_header = (void *)((intptr_t)mapped_address + header.e_phoff);
	out_info->entrypoint = (void *)(header.e_entry - start + (intptr_t)mapped_address);
	if (dynamic_ph) {
		out_info->dynamic = (const ElfW(Dyn) *)((intptr_t)mapped_address + dynamic_ph->p_vaddr - start);
		out_info->dynamic_size = dynamic_ph->p_memsz / sizeof(ElfW(Dyn));
		out_info->dynamic_offset = dynamic_ph->p_offset;
	} else {
		out_info->dynamic = 0;
		out_info->dynamic_size = 0;
		out_info->dynamic_offset = 0;
	}
	if (off_interpreter != 0) {
		out_info->interpreter = (const char *)((intptr_t)mapped_address + off_interpreter);
	} else {
		out_info->interpreter = NULL;
	}
	out_info->strtab_section_index = header.e_shstrndx;
	out_info->section_offset = header.e_shoff;
	out_info->section_entry_size = header.e_shentsize;
	out_info->section_entry_count = header.e_shnum;
	return 0;
}

void unload_binary(struct binary_info *info)
{
	if (info->phbuffer) {
		free(info->phbuffer);
	}
	fs_munmap(info->base, info->size);
}

void load_existing(struct binary_info *out_info, uintptr_t load_address)
{
	const ElfW(Ehdr) *header = (const ElfW(Ehdr) *)load_address;
	out_info->header_entry_size = header->e_phentsize;
	out_info->header_entry_count = header->e_phnum;
	out_info->phbuffer = NULL;

	uintptr_t start = UINTPTR_MAX;
	uintptr_t off_start = 0;
	uintptr_t end = 0;

	uintptr_t off_interpreter = 0;
	const ElfW(Phdr) *dynamic_ph = NULL;
	for (int i = 0; i < header->e_phnum; i++) {
		const ElfW(Phdr) *ph = (const ElfW(Phdr) *)(load_address + header->e_phoff + header->e_phentsize * i);
		switch (ph->p_type) {
			case PT_LOAD: {
				if ((uintptr_t)ph->p_vaddr <= start) {
					start = (uintptr_t)ph->p_vaddr;
					off_start = (uintptr_t)ph->p_offset;
				}
				if ((uintptr_t)ph->p_vaddr + (uintptr_t)ph->p_memsz > end) {
					end = (uintptr_t)ph->p_vaddr + (uintptr_t)ph->p_memsz;
				}
				break;
			}
			case PT_DYNAMIC: {
				dynamic_ph = ph;
				break;
			}
			case PT_INTERP: {
				off_interpreter = ph->p_offset;
				break;
			}
			case PT_GNU_STACK: {
				out_info->executable_stack = ph->p_flags & PF_X ? EXECUTABLE_STACK_REQUIRED : EXECUTABLE_STACK_PROHIBITED;
				break;
			}
		}
	}

	out_info->base = (void *)load_address;
	out_info->default_base = NULL;
	size_t total_size = end - start + off_start;
	out_info->size = total_size;
	out_info->program_header = (void *)(intptr_t)(load_address + header->e_phoff);
	out_info->entrypoint = (void *)(intptr_t)(header->e_entry + load_address);
	if (dynamic_ph) {
		out_info->dynamic = (const ElfW(Dyn) *)(load_address + dynamic_ph->p_vaddr);
		out_info->dynamic_size = dynamic_ph->p_memsz / sizeof(ElfW(Dyn));
		out_info->dynamic_offset = dynamic_ph->p_offset;
	} else {
		out_info->dynamic = 0;
		out_info->dynamic_size = 0;
		out_info->dynamic_offset = 0;
	}
	if (off_interpreter != 0) {
		out_info->interpreter = (const char *)(load_address + off_interpreter);
	} else {
		out_info->interpreter = NULL;
	}
	out_info->strtab_section_index = header->e_shstrndx;
	out_info->section_offset = header->e_shoff;
	out_info->section_entry_size = header->e_shentsize;
	out_info->section_entry_count = header->e_shnum;
}

static void apply_relr_table(struct binary_info *info, const uintptr_t *relative, size_t size)
{
	const uintptr_t *end = relative + size / sizeof(uintptr_t);
	uintptr_t base = (uintptr_t)info->base;
	uintptr_t *where = (uintptr_t *)base;
	for (; relative < end; ++relative) {
		uintptr_t entry = *relative;
		if (entry & 1) {
			for (long i = 0; (entry >>= 1) != 0; i++) {
				if (entry & 1) {
					where[i] += base;
				}
			}
			where += CHAR_BIT * sizeof(uintptr_t) - 1;
		} else {
			where = (uintptr_t *)(base + entry);
			*where++ += base;
		}
	}
}

void relocate_binary(struct binary_info *info)
{
	uintptr_t relr = 0;
	uintptr_t relrsz = 0;
	uintptr_t relrent = 0;
	uintptr_t rela = 0;
	uintptr_t relasz = 0;
	uintptr_t relaent = 0;
	const ElfW(Dyn) *dynamic = info->dynamic;
	size_t size_dynamic = info->dynamic_size;
	for (int i = 0; i < (int)size_dynamic; i++) {
		switch (dynamic[i].d_tag) {
			case DT_RELR:
				relr = dynamic[i].d_un.d_ptr;
				break;
			case DT_RELRSZ:
				relrsz = dynamic[i].d_un.d_val;
				break;
			case DT_RELRENT:
				relrent = dynamic[i].d_un.d_val;
				break;
			case DT_RELA:
				rela = dynamic[i].d_un.d_ptr;
				break;
			case DT_RELASZ:
				relasz = dynamic[i].d_un.d_val;
				break;
			case DT_RELAENT:
				relaent = dynamic[i].d_un.d_val;
				break;
		}
	}
	// apply relr
	if (relr != 0 && relrent == sizeof(uintptr_t)) {
		apply_relr_table(info, (const uintptr_t *)apply_base_address(info, relr), relrsz);
	}
	// apply rela
	uintptr_t base = (uintptr_t)info->base;
	uintptr_t rel_base = apply_base_address(info, rela);
	for (uintptr_t rel_off = 0; rel_off < relasz; rel_off += relaent) {
		const ElfW(Rel) *rel = (const ElfW(Rel) *)(rel_base + rel_off);
		if (rel->r_info == ELF_REL_RELATIVE) {
			*(uintptr_t *)(base + rel->r_offset) += base;
		}
	}
}

int apply_postrelocation_readonly(struct binary_info *info)
{
	if (info->phbuffer != NULL) {
		uintptr_t map_offset = info->base - info->default_base;
		for (size_t i = 0; i < info->header_entry_count; i++) {
			const ElfW(Phdr) *ph = (const ElfW(Phdr) *)&info->phbuffer[info->header_entry_size * i];
			if (ph->p_type != PT_GNU_RELRO) {
				continue;
			}
			uintptr_t this_min = ph->p_vaddr & PAGE_ALIGNMENT_MASK;
			uintptr_t this_max = (ph->p_vaddr + ph->p_memsz + PAGE_SIZE-1) & PAGE_ALIGNMENT_MASK;
			int protection = protection_for_pflags(ph->p_flags);
			int result = fs_mprotect((void *)(map_offset + this_min), this_max-this_min, protection);
			if (result < 0) {
				ERROR("failed remapping section with new protection", fs_strerror(result));
				return result;
			}
		}
	}
	return 0;
}

int load_dynamic_symbols(int fd, const struct binary_info *info, struct symbol_info *out_symbols)
{
	// Map the entire binary read-only
	void *mapped_address = fs_mmap(NULL, info->size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (fs_is_map_failed(mapped_address)) {
		return (intptr_t)mapped_address;
	}
	int result = parse_dynamic_symbols(info, mapped_address, out_symbols);
	if (result != 0) {
		fs_munmap(mapped_address, info->size);
	}
	out_symbols->mapping = mapped_address;
	out_symbols->mapping_size = info->size;
	return result;
}

static inline intptr_t apply_base_address_heuristic(void *base_address, intptr_t addr_or_offset)
{
	return (uintptr_t)addr_or_offset > (uintptr_t)base_address ? addr_or_offset : ((intptr_t)base_address + addr_or_offset);
}

static inline size_t symbol_count_from_gnu_hash(const struct symbol_info *info)
{
	const uint32_t *gnu_table = info->gnu_hash;
	uint32_t bucket_count = gnu_table[0];
	uint32_t symbol_offset = gnu_table[1];
	uint32_t filter_size = gnu_table[2];
	const uint64_t *filter = (const uint64_t *)&gnu_table[4];
	const uint32_t *buckets = (const uint32_t *)&filter[filter_size];
	const uint32_t *chain = &buckets[bucket_count];
	size_t count = 0;
	for (uint32_t j = 0; j < bucket_count; j++) {
		if (buckets[j] > count) {
			count = buckets[j];
		}
	}
	if (count < symbol_offset) {
		count = symbol_offset;
	} else {
		while ((chain[(count++) - symbol_offset] & 1) == 0) {
		}
	}
	return count;
}

static void load_hash(const ElfW(Word) *hash, size_t symbol_count, struct symbol_info *out_symbols)
{
	if (hash != NULL) {
		out_symbols->buckets = &hash[2];
		out_symbols->bucket_count = hash[0];
		out_symbols->symbol_count = hash[1];
		out_symbols->chains = &hash[2 + hash[0]];
	} else {
		if (symbol_count == 0 && out_symbols->gnu_hash != NULL) {
			symbol_count = symbol_count_from_gnu_hash(out_symbols);
		}
		out_symbols->buckets = NULL;
		out_symbols->bucket_count = 0;
		out_symbols->symbol_count = symbol_count;
		out_symbols->chains = 0;
	}
	out_symbols->address_ordered = NULL;
}

static void add_version(size_t index, const char *version_name, const char *library_name, struct symbol_info *out_symbols)
{
#ifdef LOADER_SYMBOL_VERSION_DEBUG
	ERROR("add version at index", (intptr_t)index);
	ERROR("name", version_name);
#endif
	if (index >= out_symbols->valid_version_count) {
		out_symbols->valid_versions = realloc(out_symbols->valid_versions, (index + 1) * sizeof(struct symbol_version_info));
		for (size_t i = out_symbols->valid_version_count; i <= index; i++) {
			out_symbols->valid_versions[i] = (struct symbol_version_info) { 0 };
		}
		out_symbols->valid_version_count = index + 1;
	}
	if (out_symbols->valid_versions[index].version_name != NULL) {
		struct symbol_version_info *next = malloc(sizeof(*next));
		*next = out_symbols->valid_versions[index];
		out_symbols->valid_versions[index].next = next;
	}
	out_symbols->valid_versions[index].version_name = version_name;
	out_symbols->valid_versions[index].library_name = library_name;
}

static void load_versions(const ElfW(Half) *versym, const ElfW(Verneed) *verneed, const ElfW(Verdef) *verdef, struct symbol_info *out_symbols)
{
	out_symbols->valid_versions = NULL;
	out_symbols->valid_version_count = 0;
	if (verneed != NULL) {
#ifdef LOADER_SYMBOL_VERSION_DEBUG
		ERROR("verneed");
#endif
		for (;;) {
			if (verneed->vn_version != 1) {
				break;
			}
			const char *library_name = &out_symbols->strings[verneed->vn_file];
			const ElfW(Vernaux) *aux = (const ElfW(Vernaux) *)((intptr_t)verneed + verneed->vn_aux);
			for (size_t i = 0; i < verneed->vn_cnt; i++) {
				size_t index = aux->vna_other & 0x7fff;
				const char *name = &out_symbols->strings[aux->vna_name];
				add_version(index, name, library_name, out_symbols);
				aux = (const ElfW(Vernaux) *)((intptr_t)aux + aux->vna_next);
			}
			if (verneed->vn_next == 0) {
				break;
			}
			verneed = (const ElfW(Verneed) *)((intptr_t)verneed + verneed->vn_next);
		}
	}
	if (verdef != NULL) {
#ifdef LOADER_SYMBOL_VERSION_DEBUG
		ERROR("verdef");
#endif
		for (;;) {
			if (verdef->vd_version != 1) {
				break;
			}
			if (verdef->vd_flags == 0) {
				size_t index = verdef->vd_ndx;
				const ElfW(Verdaux) *aux = (const ElfW(Verdaux) *)((intptr_t)verdef + verdef->vd_aux);
				for (size_t i = 0; i < verdef->vd_cnt; i++) {
					const char *name = &out_symbols->strings[aux->vda_name];
					add_version(index, name, NULL, out_symbols);
					aux = (const ElfW(Verdaux) *)((intptr_t)aux + aux->vda_next);
				}
			}
			if (verdef->vd_next == 0) {
				break;
			}
			verdef = (const ElfW(Verdef) *)((intptr_t)verdef + verdef->vd_next);
		}
	}
	if (versym != NULL && (verneed != NULL || verdef != NULL)) {
		out_symbols->symbol_versions = versym;
	} else {
		out_symbols->symbol_versions = NULL;
	}
}

int parse_dynamic_symbols(const struct binary_info *info, void *mapped_address, struct symbol_info *out_symbols)
{
	// Find sections
	ElfW(Addr) symtab = 0;
	ElfW(Addr) syment = 0;
	ElfW(Addr) strtab = 0;
	size_t strtab_size = 0;
	ElfW(Addr) hash = 0;
	ElfW(Addr) gnu_hash = 0;
	ElfW(Addr) init_functions = 0;
	ElfW(Addr) init_function_size = 0;
	ElfW(Addr) versym = 0;
	ElfW(Addr) verneed = 0;
	ElfW(Addr) verdef = 0;
	const ElfW(Dyn) *dynamic = info->dynamic;
	size_t dynamic_size = info->dynamic_size;
	for (size_t i = 0; i < dynamic_size; i++) {
		switch (dynamic[i].d_tag) {
			case DT_SYMTAB:
				symtab = dynamic[i].d_un.d_ptr;
				break;
			case DT_SYMENT:
				syment = dynamic[i].d_un.d_val;
				break;
			case DT_STRTAB:
				strtab = dynamic[i].d_un.d_ptr;
				break;
			case DT_STRSZ:
				strtab_size = dynamic[i].d_un.d_val;
				break;
			case DT_HASH:
				hash = dynamic[i].d_un.d_ptr;
				break;
			case DT_GNU_HASH:
				gnu_hash = dynamic[i].d_un.d_ptr;
				break;
			case DT_INIT_ARRAY:
				init_functions = dynamic[i].d_un.d_ptr;
				break;
			case DT_INIT_ARRAYSZ:
				init_function_size = dynamic[i].d_un.d_val;
				break;
			case DT_VERSYM:
				versym = dynamic[i].d_un.d_ptr;
				break;
			case DT_VERNEED:
				verneed = dynamic[i].d_un.d_ptr;
				break;
			case DT_VERDEF:
				verdef = dynamic[i].d_un.d_ptr;
				break;
		}
	}
	if (symtab == 0 || syment == 0 || strtab == 0 || (hash == 0 && gnu_hash == 0)) {
		return -EINVAL;
	}
	out_symbols->gnu_hash = gnu_hash != 0 ? (void *)apply_base_address_heuristic(mapped_address, gnu_hash) : NULL;
	out_symbols->mapping = NULL;
	out_symbols->mapping_size = 0;
	out_symbols->symbols = apply_base_address_heuristic(mapped_address, symtab);
	out_symbols->symbol_stride = syment;
	out_symbols->strings = (const char *)apply_base_address_heuristic(mapped_address, strtab);
	out_symbols->strings_size = strtab_size;
	out_symbols->init_functions = (const void **)apply_base_address_heuristic(mapped_address, init_functions);
	out_symbols->init_function_count = init_function_size / sizeof(void *);
	load_hash(hash != 0 ? (const ElfW(Word) *)apply_base_address_heuristic(mapped_address, hash) : 0, 0, out_symbols);
	load_versions(versym != 0 ? (const ElfW(Half) *)apply_base_address_heuristic(mapped_address, versym) : NULL, verneed != 0 ? (const ElfW(Verneed) *)apply_base_address_heuristic(mapped_address, verneed) : NULL, verdef != 0 ? (const ElfW(Verdef) *)apply_base_address_heuristic(mapped_address, verdef) : NULL, out_symbols);
	return 0;
}

static void parse_section_symbols(void *mapped_address, const ElfW(Shdr) *symbol_section, const ElfW(Shdr) *string_section, const ElfW(Shdr) *hash_section, const ElfW(Shdr) *version_section, const ElfW(Shdr) *version_need_section, const ElfW(Shdr) *version_def_section, struct symbol_info *out_symbols);

int load_section_symbols(int fd, struct binary_info *info, const struct section_info *section_info, bool load_hash, struct symbol_info *out_symbols)
{
	const ElfW(Shdr) *symtab = NULL;
	const ElfW(Shdr) *strtab = NULL;
	const ElfW(Shdr) *hash_section = NULL;
	const ElfW(Shdr) *gnu_hash_section = NULL;
	const ElfW(Shdr) *version_section = NULL;
	const ElfW(Shdr) *version_need_section = NULL;
	const ElfW(Shdr) *version_def_section = NULL;
	for (size_t i = 0; i < info->section_entry_count; i++) {
		const ElfW(Shdr) *section = (const ElfW(Shdr) *)((uintptr_t)section_info->sections + i * info->section_entry_size);
		switch (section->sh_type) {
			case SHT_SYMTAB:
				symtab = section;
				break;
			case SHT_STRTAB: {
				const char *name = &section_info->strings[section->sh_name];
				if (fs_strcmp(name, ".strtab") == 0) {
					strtab = section;
				}
				break;
			}
			case SHT_HASH:
				if (load_hash) {
					hash_section = section;
				}
				break;
			case SHT_GNU_HASH:
				if (load_hash) {
					gnu_hash_section = section;
				}
				break;
			case SHT_GNU_versym:
				version_section = section;
				break;
			case SHT_GNU_verneed:
				version_need_section = section;
				break;
			case SHT_GNU_verdef:
				version_def_section = section;
				break;
		}
	}
	if (symtab == NULL || strtab == NULL) {
		return -EINVAL;
	}
	struct fs_stat stat;
	intptr_t result = fs_fstat(fd, &stat);
	if (result < 0) {
		return result;
	}
	// Map the entire binary read-only
	void *mapped_address = fs_mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (fs_is_map_failed(mapped_address)) {
		return (intptr_t)mapped_address;
	}
	parse_section_symbols(mapped_address, symtab, strtab, hash_section, version_section, version_need_section, version_def_section, out_symbols);
	out_symbols->gnu_hash = gnu_hash_section != NULL ? (void *)((uintptr_t)mapped_address + gnu_hash_section->sh_offset) : NULL;
	out_symbols->mapping = mapped_address;
	out_symbols->mapping_size = stat.st_size;
	return 0;
}

static void parse_section_symbols(void *mapped_address, const ElfW(Shdr) *symbol_section, const ElfW(Shdr) *string_section, const ElfW(Shdr) *hash_section, const ElfW(Shdr) *version_section, const ElfW(Shdr) *version_need_section, const ElfW(Shdr) *version_def_section, struct symbol_info *out_symbols)
{
	out_symbols->gnu_hash = NULL;
	out_symbols->mapping = NULL;
	out_symbols->mapping_size = 0;
	out_symbols->symbols = (uintptr_t)mapped_address + symbol_section->sh_offset;
	out_symbols->symbol_stride = symbol_section->sh_entsize;
	out_symbols->strings = (const char *)mapped_address + string_section->sh_offset;
	out_symbols->strings_size = string_section->sh_size;
	out_symbols->init_functions = NULL;
	out_symbols->init_function_count = 0;
	load_hash(hash_section != NULL ? (const ElfW(Word) *)((uintptr_t)mapped_address + hash_section->sh_offset) : NULL, symbol_section->sh_size / symbol_section->sh_entsize, out_symbols);
	// TODO: use sh_link
	load_versions(version_section != NULL ? (const ElfW(Half) *)((uintptr_t)mapped_address + symbol_section->sh_offset) : NULL, version_need_section != NULL ? (const ElfW(Verneed) *)((uintptr_t)mapped_address + version_need_section->sh_offset) : NULL, version_def_section != NULL ? (const ElfW(Verdef) *)((uintptr_t)mapped_address + version_def_section->sh_offset) : NULL, out_symbols);
}

unsigned long elf_hash(const unsigned char *name)
{
	unsigned long h = 0, g;
	while (*name) {
		h = (h << 4) + *name++;
		if ((g = h & 0xf0000000)) {
			h ^= g >> 24;
		}
		h &= ~g;
	}
	return h;
}

uint32_t gnu_hash(const char *name)
{
	uint32_t h = 5381;
	while (*name) {
		h += (h << 5) + (uint8_t)*name++;
	}
	return h;
}

void free_symbols(struct symbol_info *symbols)
{
	if (symbols->mapping) {
		fs_munmap((void *)symbols->mapping, symbols->mapping_size);
	}
	if (symbols->address_ordered) {
		free(symbols->address_ordered);
	}
	for (size_t i = 0; i < symbols->valid_version_count; i++) {
		const struct symbol_version_info *version = symbols->valid_versions[i].next;
		while (version) {
			const struct symbol_version_info *next = version->next;
			free((void *)version);
			version = next;
		}
	}
	free(symbols->valid_versions);
}

const char *symbol_name(const struct symbol_info *symbols, const ElfW(Sym) *symbol)
{
	if (symbol == NULL) {
		return NULL;
	}
	size_t offset = symbol->st_name;
	if (offset > symbols->strings_size) {
		DIE("symbol offset is beyond the end of the strings table", offset);
	}
	return &symbols->strings[offset];
}

enum version_match {
	VERSION_MATCH_NONE,
	VERSION_MATCH_EXACT,
	VERSION_MATCH_IF_ONLY,
};

static inline enum version_match versions_match(__attribute__((unused)) const char *symbol_name, const char *version_to_query, const struct symbol_info *symbols, uint32_t symbol_index)
{
	if (symbols->symbol_versions == NULL) {
		return version_to_query == NULL ? VERSION_MATCH_EXACT : VERSION_MATCH_IF_ONLY;
	}
	ElfW(Half) index = symbols->symbol_versions[symbol_index] & 0x7fff;
	// if (index & 0x8000) {
	// 	return VERSION_MATCH_NONE;
	// }
	if (version_to_query == NULL) {
		return index == 1 || index == 2 ? VERSION_MATCH_EXACT : VERSION_MATCH_IF_ONLY;
	}
#ifdef LOADER_SYMBOL_VERSION_DEBUG
	ERROR("querying version", version_to_query);
	ERROR("for symbol", symbol_name);
#endif
	struct symbol_version_info first = symbol_version_for_index(symbols, index);
	const struct symbol_version_info *version_to_match = &first;
	do {
		if (version_to_match->version_name == NULL) {
			return VERSION_MATCH_NONE;
		}
#ifdef LOADER_SYMBOL_VERSION_DEBUG
		ERROR("against", version_to_match->version_name);
		if (version_to_match->library_name != NULL) {
			ERROR("in", version_to_match->library_name);
		}
#endif
		if (fs_strcmp(version_to_query, version_to_match->version_name) == 0) {
			return VERSION_MATCH_EXACT;
		}
		version_to_match = version_to_match->next;
	} while(version_to_match != NULL);
	return VERSION_MATCH_NONE;
}

static inline const ElfW(Sym) *find_elf_symbol(const struct symbol_info *symbols, const char *name_to_find, const char *version_to_find)
{
	const uint32_t *gnu_table = symbols->gnu_hash;
	const ElfW(Sym) *fallback_result = NULL;
	if (gnu_table != NULL) {
		uint32_t hash = gnu_hash(name_to_find);
		uint32_t bucket_count = gnu_table[0];
		uint32_t symbol_offset = gnu_table[1];
		uint32_t filter_size = gnu_table[2];
		uint32_t filter_shift = gnu_table[3];
		const uint64_t *filter = (const uint64_t *)&gnu_table[4];
		const uint32_t *buckets = (const uint32_t *)&filter[filter_size];
		const uint32_t *chain = &buckets[bucket_count];
		uint64_t mask = (uint64_t)1 << (hash % 64);
		mask |= (uint64_t)1 << ((hash >> filter_shift) % 64);
		if ((filter[(hash / 64) % filter_size] & mask) != mask) {
			return NULL;
		}
		uint32_t i = buckets[hash % bucket_count];
	    if (i < symbol_offset) {
			return NULL;
		}
		for (;; i++) {
			uint32_t entry = chain[i - symbol_offset];
			bool end_of_chain = (entry & 1) != 0;
			if ((entry|1) == (hash|1)) {
				const ElfW(Sym) *symbol = (const ElfW(Sym) *)(symbols->symbols + i * symbols->symbol_stride);
				if (fs_strcmp(name_to_find, symbol_name(symbols, symbol)) == 0) {
					switch (versions_match(name_to_find, version_to_find, symbols, i)) {
						case VERSION_MATCH_NONE:
#ifdef LOADER_SYMBOL_VERSION_DEBUG
							ERROR("VERSION_MATCH_NONE for GNU", name_to_find);
							if (version_to_find != NULL) {
								ERROR("version to find is", version_to_find);
							}
#endif
							break;
						case VERSION_MATCH_EXACT:
							return symbol;
						case VERSION_MATCH_IF_ONLY:
#ifdef LOADER_SYMBOL_VERSION_DEBUG
							ERROR("VERSION_MATCH_IF_ONLY for GNU", name_to_find);
							if (version_to_find != NULL) {
								ERROR("version to find is", version_to_find);
							}
#endif
							fallback_result = fallback_result ? NULL : symbol;
							break;
					}
				}
			}
			if (end_of_chain) {
				// end of chain
				break;
			}
		}
	} else if (LIKELY(symbols->buckets != NULL)) {
		size_t i = symbols->buckets[elf_hash((const unsigned char *)name_to_find) % symbols->bucket_count];
		do {
			const ElfW(Sym) *symbol = (const ElfW(Sym) *)(symbols->symbols + i * symbols->symbol_stride);
			size_t next_i = symbols->chains[i];
			if (fs_strcmp(name_to_find, symbol_name(symbols, symbol)) == 0) {
				switch (versions_match(name_to_find, version_to_find, symbols, i)) {
					case VERSION_MATCH_NONE:
#ifdef LOADER_SYMBOL_VERSION_DEBUG
						ERROR("VERSION_MATCH_NONE for buckets", name_to_find);
						if (version_to_find != NULL) {
							ERROR("version to find is", version_to_find);
						}
#endif
						break;
					case VERSION_MATCH_EXACT:
						return symbol;
					case VERSION_MATCH_IF_ONLY:
#ifdef LOADER_SYMBOL_VERSION_DEBUG
						ERROR("VERSION_MATCH_IF_ONLY for buckets", name_to_find);
						if (version_to_find != NULL) {
							ERROR("version to find is", version_to_find);
						}
#endif
						fallback_result = fallback_result ? NULL : symbol;
						break;
				}
			}
			i = next_i;
		} while (i != STN_UNDEF);
	} else {
		// TODO: this is really slow, fix this
		for (size_t i = 0; i < symbols->symbol_count; i++) {
			const ElfW(Sym) *symbol = (const ElfW(Sym) *)(symbols->symbols + i * symbols->symbol_stride);
			if (fs_strcmp(name_to_find, symbol_name(symbols, symbol)) == 0) {
				switch (versions_match(name_to_find, version_to_find, symbols, i)) {
					case VERSION_MATCH_NONE:
#ifdef LOADER_SYMBOL_VERSION_DEBUG
						ERROR("VERSION_MATCH_NONE for linear", name_to_find);
						if (version_to_find != NULL) {
							ERROR("version to find is", version_to_find);
						}
#endif
						break;
					case VERSION_MATCH_EXACT:
						return symbol;
					case VERSION_MATCH_IF_ONLY:
#ifdef LOADER_SYMBOL_VERSION_DEBUG
						ERROR("VERSION_MATCH_IF_ONLY for linear", name_to_find);
						if (version_to_find != NULL) {
							ERROR("version to find is", version_to_find);
						}
#endif
						fallback_result = fallback_result ? NULL : symbol;
						break;
				}
			}
		}
	}
	return fallback_result;
}

__attribute__((noinline))
void *find_symbol(const struct binary_info *info, const struct symbol_info *symbols, const char *name_to_find, const char *version_to_find, const ElfW(Sym) **out_symbol)
{
	const ElfW(Sym) *symbol = find_elf_symbol(symbols, name_to_find, version_to_find);
	if (out_symbol) {
		*out_symbol = symbol;
	}
	if (symbol == NULL) {
		return NULL;
	}
	if (symbol->st_value == 0 || symbol->st_shndx == SHN_UNDEF) {
		return NULL;
	}
	return (void *)((uintptr_t)info->base + symbol->st_value - (uintptr_t)info->default_base);
}

void *find_next_symbol(const struct binary_info *info, const struct symbol_info *symbols, const char *name_to_find, const ElfW(Sym) **out_symbol)
{
	// if (symbols->buckets != NULL) {
	// 	size_t index;
	// 	if (*out_symbol == NULL) {
	// 		index = symbols->buckets[elf_hash((const unsigned char *)name_to_find) % symbols->bucket_count];
	// 	} else {
	// 		index = (uintptr_t)(*out_symbol - symbols->symbols) / symbols->symbol_stride;
	// 		index = symbols->chains[index];
	// 	}
	// 	do {
	// 		const ElfW(Sym) *symbol = (const ElfW(Sym) *)(symbols->symbols + index * symbols->symbol_stride);
	// 		if (fs_strcmp(name_to_find, symbol_name(symbols, symbol)) == 0) {
	// 			if (out_symbol) {
	// 				*out_symbol = symbol;
	// 			}
	// 			if (symbol->st_value == 0) {
	// 				return NULL;
	// 			}
	// 			return (void *)((uintptr_t)info->base + symbol->st_value - (uintptr_t)info->default_base);
	// 		}
	// 		index = symbols->chains[index];
	// 	} while (index != STN_UNDEF);
	// 	return NULL;
	// }
	// TODO: this is really slow, fix this
	size_t i;
	if (*out_symbol == NULL) {
		i = 0;
	} else {
		i = ((uintptr_t)*out_symbol - symbols->symbols) / symbols->symbol_stride + 1;
	}
	for (; i < symbols->symbol_count; i++) {
		const ElfW(Sym) *symbol = (const ElfW(Sym) *)(symbols->symbols + i * symbols->symbol_stride);
		if (symbol->st_value != 0 && fs_strcmp(name_to_find, symbol_name(symbols, symbol)) == 0) {
			if (out_symbol) {
				*out_symbol = symbol;
			}
			return (void *)((uintptr_t)info->base + symbol->st_value - (uintptr_t)info->default_base);
		}
	}
	return NULL;
}

bool symbol_info_contains_symbol(const struct symbol_info *symbols, const ElfW(Sym) *symbol)
{
	return symbols->symbols <= (uintptr_t)symbol && (uintptr_t)symbol < symbols->symbols + symbols->symbol_stride * symbols->symbol_count;
}

#ifdef INDEX_SYMBOLS

#define SYMBOL_INDEX_BITS 24

static int compare_uint64_t(const void *l, const void *r, __attribute__((unused)) void *unused)
{
	uint64_t lval = *(const uint64_t *)l;
	uint64_t rval = *(const uint64_t *)r;
	if (lval < rval) {
		return -1;
	}
	if (lval == rval) {
		return 0;
	}
	return 1;
}

static inline bool bsearch_symbol_by_address_callback(int index, void *search_value, void *ordered_void)
{
	const uint64_t *ordered = (const uint64_t *)ordered_void;
	return ordered[index] > (uint64_t)search_value;
}

#endif

void *find_symbol_by_address(const struct binary_info *info, const struct symbol_info *symbols, const void *addr, const ElfW(Sym) **out_symbol)
{
	if ((uintptr_t)addr < (uintptr_t)info->base) {
		return NULL;
	}
	uintptr_t value = (uintptr_t)addr - (uintptr_t)info->base;
	if (value > info->size) {
		return NULL;
	}
	value += (uintptr_t)info->default_base;
	size_t count = symbols->symbol_count;
	if (count == 0) {
		return NULL;
	}
	size_t stride = symbols->symbol_stride;
	uintptr_t symbol_addr = symbols->symbols;
#ifdef INDEX_SYMBOLS
	uint64_t *ordered = symbols->address_ordered;
	if (ordered == NULL) {
		ordered = malloc(count * sizeof(uint64_t));
		((struct symbol_info *)symbols)->address_ordered = ordered;
		uintptr_t next_symbol = symbol_addr;
		for (size_t i = 0; i < count; i++, next_symbol += stride) {
			const ElfW(Sym) *symbol = (const ElfW(Sym) *)next_symbol;
			ordered[i] = i | (symbol->st_value << SYMBOL_INDEX_BITS);
		}
		qsort_r_freestanding(ordered, count, sizeof(uint64_t), compare_uint64_t, NULL);
	}
	uint64_t search_value = (value + 1) << SYMBOL_INDEX_BITS;
	for (int i = bsearch_bool(count, (void *)search_value, ordered, bsearch_symbol_by_address_callback); i != 0; i--) {
		uint64_t index = ordered[i-1] & ~(~0ull << SYMBOL_INDEX_BITS);
		const ElfW(Sym) *symbol = (const ElfW(Sym) *)(symbol_addr + index * stride);
		if ((symbol->st_value <= value) && (symbol->st_value + symbol->st_size) > value) {
			if (out_symbol) {
				*out_symbol = symbol;
			}
			return (void *)((uintptr_t)info->base + symbol->st_value - (uintptr_t)info->default_base);
		}
		if (ordered[i-1] < (value << SYMBOL_INDEX_BITS)) {
			break;
		}
	}
#else
	for (size_t i = 0; i < count; i++, symbol_addr += stride) {
		const ElfW(Sym) *symbol = (const ElfW(Sym) *)symbol_addr;
		if ((symbol->st_value <= value) && (symbol->st_value + symbol->st_size) > value) {
			if (out_symbol) {
				*out_symbol = symbol;
			}
			return (void *)((uintptr_t)info->base + symbol->st_value - (uintptr_t)info->default_base);
		}
	}
#endif
	return NULL;
}

int load_section_info(int fd, const struct binary_info *info, struct section_info *out_section_info)
{
	int size = info->section_entry_size * info->section_entry_count;
	void *buffer = malloc(size);
	if (buffer == NULL) {
		return -EINVAL;
	}
	int result = fs_pread_all(fd, buffer, size, info->section_offset);
	if (result != size) {
		free(buffer);
		if (result >= 0) {
			return -EINVAL;
		}
		return result;
	}
	const ElfW(Shdr) *strtab = (const ElfW(Shdr) *)((char *)buffer + info->strtab_section_index * info->section_entry_size);
	int str_size = strtab->sh_size;
	void *str_buffer = malloc(str_size);
	if (str_buffer == NULL) {
		free(buffer);
		return -ENOMEM;
	}
	result = fs_pread_all(fd, str_buffer, str_size, strtab->sh_offset);
	if (result != str_size) {
		free(buffer);
		if (result >= 0) {
			return -EINVAL;
		}
		return result;
	}
	out_section_info->sections = buffer;
	out_section_info->strings = str_buffer;
	return 0;
}

void free_section_info(const struct section_info *section_info)
{
	free((void *)section_info->strings);
	free((void *)section_info->sections);
}

__attribute__((noinline))
const ElfW(Shdr) *find_section(const struct binary_info *info, const struct section_info *section_info, const char *name)
{
	for (size_t i = 0; i < info->section_entry_count; i++) {
		const ElfW(Shdr) *section = (const ElfW(Shdr) *)((char *)section_info->sections + i * info->section_entry_size);
		if (fs_strcmp(&section_info->strings[section->sh_name], name) == 0) {
			return section;
		}
	}
	return NULL;
}

// verify_allowed_to_exec verifies that the target file is executable by the current user/group
int verify_allowed_to_exec(int fd, struct fs_stat *stat, uid_t uid, gid_t gid) {
	struct fs_statfs mount_stat;
	int result = fs_fstatfs(fd, &mount_stat);
	if (result < 0) {
		return result;
	}
#ifdef ST_NOEXEC
	if (mount_stat.f_flags & ST_NOEXEC) {
		// Filesystem is mounted noexec
		return -EACCES;
	}
#endif
#ifdef MNT_NOEXEC
	if (mount_stat.f_flags & MNT_NOEXEC) {
		// Filesystem is mounted noexec
		return -EACCES;
	}
#endif
	result = fs_fstat(fd, stat);
	if (result < 0) {
		return result;
	}
	if ((stat->st_mode & S_IXUSR) && (stat->st_uid == uid)) {
		// User has permission to execute
		return 0;
	}
	if ((stat->st_mode & S_IXGRP) && (stat->st_gid == gid)) {
		// Group has permission to execute
		return 0;
	}
	if (stat->st_mode & S_IXOTH) {
		// Everyone has permission to execute
		return 0;
	}
	return -EACCES;
}

static inline uintptr_t read_uleb128(void **cursor)
{
	uintptr_t result = 0;
	int shift = 0;
	for (;;) {
		unsigned char val = *(char *)*cursor;
		(*cursor)++;
		result |= (val & 0x7f) << shift;
		if ((val & 0x80) == 0) {
			return result;
		}
		shift += 7;
	}
}

static inline intptr_t read_sleb128(void **cursor)
{
	intptr_t result = 0;
	int shift = 0;
	for (;;) {
		unsigned char val = *(char *)*cursor;
		(*cursor)++;
		result |= (val & 0x7f) << shift;
		if ((val & 0x80) == 0) {
			if (shift < 64 && ((val & 0x40) != 0)) {
			    // sign extend the result
			    result |= ~(uintptr_t)0 << shift;
			}
			return result;
		}
		shift += 7;
	}
}

__attribute__((always_inline))
static inline uintptr_t read_offset_and_advance(void **cursor, uintptr_t format)
{
	switch (format & 0xf) {
		case DW_EH_PE_uleb128:
			return read_uleb128(cursor);
		case DW_EH_PE_udata2: {
			uintptr_t result = *(const uint16_t *)*cursor;
			*cursor += sizeof(uint16_t);
			return result;
		}
		case DW_EH_PE_udata4: {
			uintptr_t result = *(const uint32_t *)*cursor;
			*cursor += sizeof(uint32_t);
			return result;
		}
		case DW_EH_PE_udata8: {
			uintptr_t result = *(const uint64_t *)*cursor;
			*cursor += sizeof(uint64_t);
			return result;
		}
		case DW_EH_PE_sleb128:
			return read_sleb128(cursor);
		case DW_EH_PE_sdata2: {
			uintptr_t result = *(const int16_t *)*cursor;
			*cursor += sizeof(int16_t);
			return result;
		}
		case DW_EH_PE_sdata4: {
			uintptr_t result = *(const int32_t *)*cursor;
			*cursor += sizeof(int32_t);
			return result;
		}
		case DW_EH_PE_sdata8: {
			uintptr_t result = *(const int64_t *)*cursor;
			*cursor += sizeof(int64_t);
			return result;
		}
		default:
			DIE("unknown format", format & 0xf);
			return 0;
	}
}

static uintptr_t read_pointer_and_advance(const struct frame_info *frame_info, void **cursor, uintptr_t format)
{
	if (format == DW_EH_PE_omit) {
		return 0;
	}
	if (format == DW_EH_PE_ptr) {
		uintptr_t result = *(const uintptr_t *)*cursor;
		*cursor += sizeof(uintptr_t);
		return result;
	}
	switch (format & 0xf0) {
		case DW_EH_PE_absptr:
			return read_offset_and_advance(cursor, format);
		case DW_EH_PE_pcrel: {
			uintptr_t base = (uintptr_t)*cursor;
			return base + read_offset_and_advance(cursor, format);
		}
		case DW_EH_PE_datarel:
			return frame_info->data_base_address + read_offset_and_advance(cursor, format);
		case DW_EH_PE_textrel:
			return frame_info->text_base_address + read_offset_and_advance(cursor, format);
		default:
			DIE("unknown format", format & 0xf0);
	}
}

struct eh_frame_hdr {
	uint8_t version;
	uint8_t eh_frame_ptr_enc;
	uint8_t fde_count_enc;
	uint8_t table_enc;
};

int load_frame_info(int fd, const struct binary_info *binary, const struct section_info *section_info, struct frame_info *out_info)
{
	(void)fd;
	const ElfW(Shdr) *section = find_section(binary, section_info, ".eh_frame");
	if (section == NULL) {
		return -ENOENT;
	}
	void *data = (void *)apply_base_address(binary, section->sh_addr);
	uintptr_t data_base_address = 0;
	const ElfW(Shdr) *header_section = find_section(binary, section_info, ".eh_frame_hdr");
	bool supported_eh_frame_hdr = false;
	if (header_section != NULL) {
		data_base_address = apply_base_address(binary, header_section->sh_addr);
		const struct eh_frame_hdr *hdr = (const struct eh_frame_hdr *)data_base_address;
		if (hdr->version == 1 && hdr->eh_frame_ptr_enc == (DW_EH_PE_pcrel | DW_EH_PE_sdata4) && hdr->fde_count_enc == DW_EH_PE_udata4 && hdr->table_enc == (DW_EH_PE_datarel | DW_EH_PE_sdata4)) {
			supported_eh_frame_hdr = true;
		}
	}
	uintptr_t text_base_address = 0;
	const ElfW(Shdr) *text_section = find_section(binary, section_info, ".text");
	if (text_section != NULL) {
		text_base_address = apply_base_address(binary, text_section->sh_addr);
	}
	*out_info = (struct frame_info) {
		.data = data,
		.size = section->sh_size,
		.data_base_address = data_base_address,
		.text_base_address = text_base_address,
		.supported_eh_frame_hdr = supported_eh_frame_hdr,
	};
	return 0;
}

void free_frame_info(struct frame_info *info)
{
	(void)info;
}

struct eh_frame_table_entry {
	int32_t address_offset;
	int32_t fde_offset;
};

static bool compare_table_entry(int i, void *entries, void *search_value)
{
	return (intptr_t)((const struct eh_frame_table_entry *)entries)[i].address_offset > (intptr_t)search_value;
}

bool find_containing_frame_info(struct frame_info *info, const void *address, struct frame_details *out_frame)
{
	if (info->supported_eh_frame_hdr) {
		uintptr_t eh_frame_hdr = info->data_base_address;
		uintptr_t entry_count_ptr = eh_frame_hdr + sizeof(struct eh_frame_hdr) + sizeof(uint32_t);
		uint32_t entry_count = *(const uint32_t *)entry_count_ptr;
		const struct eh_frame_table_entry *table = (const struct eh_frame_table_entry *)(entry_count_ptr + sizeof(uint32_t));
		int larger_index = bsearch_bool(entry_count, (void *)table, (void *)((uintptr_t)address - eh_frame_hdr), compare_table_entry);
		if (larger_index == 0) {
			return false;
		}
		void *current = (void *)(eh_frame_hdr + table[larger_index-1].fde_offset);
		current += sizeof(uint32_t) + sizeof(uint32_t);
		uintptr_t frame_location = read_pointer_and_advance(info, &current, DW_EH_PE_pcrel | DW_EH_PE_sdata4);
		uintptr_t frame_size = read_offset_and_advance(&current, DW_EH_PE_udata4);
		if (frame_location <= (uintptr_t)address) {
			if (frame_location + frame_size > (uintptr_t)address) {
				*out_frame = (struct frame_details){
					.address = (const void *)frame_location,
					.size = frame_size,
				};
				return true;
			}
		}
		return false;
	}
	uintptr_t pointer_format = DW_EH_PE_ptr;
	void *data = info->data;
	size_t size = info->size;
	for (uintptr_t cie_offset = 0; cie_offset < size;) {
		void *current = data + cie_offset;
		// read length
		uint32_t length = *(const uint32_t *)current;
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
			uintptr_t frame_location = read_pointer_and_advance(info, &current, pointer_format);
			uintptr_t frame_size = read_offset_and_advance(&current, pointer_format);
			if (frame_location <= (uintptr_t)address) {
				if (frame_location + frame_size > (uintptr_t)address) {
					*out_frame = (struct frame_details){
						.address = (const void *)frame_location,
						.size = frame_size,
					};
					return true;
				}
			}
		}
		cie_offset += sizeof(uint32_t) + length;
	}
	return false;
}
