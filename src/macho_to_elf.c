#include "macho_to_elf.h"

#include "axon.h"
#include "macho.h"

#include <mach-o/nlist.h>
#include <mach-o/fixup-chains.h>

AXON_BOOTSTRAP_ASM

static inline int translate_vm_prot(int vm_prot)
{
	int result = 0;
	if (vm_prot & VM_PROT_READ) {
		result |= PF_R;
	}
	if (vm_prot & VM_PROT_WRITE) {
		result |= PF_W;
	}
	if (vm_prot & VM_PROT_EXECUTE) {
		result |= PF_X;
	}
	return result;
}

#define ALIGN_UP(value, align) (((value) + align - 1) & ~(align - 1))

#pragma GCC push_options
#pragma GCC optimize("-fomit-frame-pointer")
__attribute__((noinline, visibility("hidden"))) int main(__attribute__((unused)) int argc, char *argv[], char *envp[])
{
	if (argc != 3) {
		DIE("expected three arguments");
	}
	// open mach-o binary
	int fd = fs_open(argv[1], O_RDONLY|O_CLOEXEC, 0);
	if (fd < 0) {
		DIE("failed to open ", argv[1], ": ", fs_strerror(fd));
	}
	// load mach-o binary
	struct macho_binary_info info;
	int result = load_macho_binary(fd, &info);
	fs_close(fd);
	if (result < 0) {
		DIE("failed to load macho binary");
	}
	const struct mach_header_64 *mach_header = info.base;
	size_t load_command_count = mach_header->ncmds;
	size_t macho_segment_count = 0;
	uintptr_t macho_address_base = ~(uintptr_t)0;
	size_t offset = sizeof(struct mach_header_64);
	const struct symtab_command *symtab = NULL;
	const struct dysymtab_command *dysymtab = NULL;
	const struct segment_command_64 *linkedit = NULL;
	const struct segment_command_64 *text = NULL;
	const struct segment_command_64 *data_const = NULL;
	const struct linkedit_data_command *chained_fixups = NULL;
	for (size_t i = 0; i < load_command_count; i++) {
		const some_load_command *lc = info.base + offset;
		switch (lc->command.cmd) {
		case LC_SEGMENT_64:
			macho_segment_count++;
			if (lc->segment.vmaddr < macho_address_base) {
				macho_address_base = lc->segment.vmaddr;
			}
			if (fs_strcmp(lc->segment.segname, "__LINKEDIT") == 0) {
				linkedit = &lc->segment;
			}
			if (fs_strcmp(lc->segment.segname, "__TEXT") == 0) {
				text = &lc->segment;
			}
			if (fs_strcmp(lc->segment.segname, "__DATA_CONST") == 0) {
				data_const = &lc->segment;
			}
			break;
		case LC_SYMTAB:
			symtab = &lc->symtab;
			break;
		case LC_DYSYMTAB:
			dysymtab = &lc->dysymtab;
			break;
		case LC_DYLD_CHAINED_FIXUPS:
			chained_fixups = &lc->linkedit_data;
			break;
		}
		offset += (lc->command.cmdsize + 0x7) & ~0x7;
	}
	if (symtab == NULL) {
		DIE("missing LC_SYMTAB");
	}
	if (dysymtab == NULL) {
		DIE("missing LC_DYSYMTAB");
	}
	if (linkedit == NULL) {
		DIE("missing __LINKEDIT segment");
	}
	if (text == NULL) {
		DIE("missing __TEXT segment");
	}
	if (chained_fixups == NULL) {
		DIE("missing LC_DYLD_CHAINED_FIXUPS");
	}
	ERROR("text vmoffset from macho_address_base: ", (uint64_t)text->vmaddr - macho_address_base);
	size_t fixups_offset = chained_fixups->dataoff;
	ERROR("fixups_offset: ", fixups_offset);
	const struct dyld_chained_fixups_header *fixups_header = info.base + chained_fixups->dataoff;
	ERROR("fixups_header->fixups_version: ", fixups_header->fixups_version);
	ERROR("fixups_header->starts_offset: ", fixups_header->starts_offset);
	size_t starts_offset = fixups_offset + fixups_header->starts_offset;
	const struct dyld_chained_starts_in_image *starts = info.base + starts_offset;
	ERROR("seg count: ", starts->seg_count);
	void *first_seg_starts = info.base + starts_offset;// + offsetof(struct dyld_chained_starts_in_image, seg_info_offset) + starts->seg_count * sizeof(starts->seg_info_offset[0]);
	for (int i = 0; i < starts->seg_count; i++) {
		ERROR("starts->seg_info_offset[", i, "]: ", starts->seg_info_offset[i]);
		if (starts->seg_info_offset[i] == 0) {
			ERROR("no fixups");
		} else {
			const struct dyld_chained_starts_in_segment *seg_starts = first_seg_starts + starts->seg_info_offset[i];
			ERROR("size: ", (uint32_t)seg_starts->size);
			ERROR("page_size: ", (uint32_t)seg_starts->page_size);
			ERROR("page_count: ", (uint32_t)seg_starts->page_count);
			ERROR("segment_offset: ", (uint64_t)seg_starts->segment_offset);
			const uint16_t *chain_starts = first_seg_starts + starts->seg_info_offset[i] + offsetof(struct dyld_chained_starts_in_segment, page_start) + seg_starts->page_count * sizeof(seg_starts->page_start[i]);
			for (int j = 0; j < seg_starts->page_count; j++) {
				ERROR("page_start[", j, "]: ", (uint32_t)seg_starts->page_start[j]);
				if (seg_starts->page_start[j] != DYLD_CHAINED_PTR_START_NONE) {
					if (seg_starts->page_start[j] & DYLD_CHAINED_PTR_START_MULTI) {
						ERROR("chain_start: ", (uint32_t)chain_starts[seg_starts->page_start[j]]);
						DIE("DYLD_CHAINED_PTR_START_MULTI is not supported");
					}
					union {
						struct dyld_chained_ptr_64_rebase rebase;
						struct dyld_chained_ptr_64_bind bind;
					} *chain = info.base + data_const->fileoff + seg_starts->page_start[j];
					for (;;) {
						ERROR("chain: ", *(const uintptr_t *)chain);
						if (chain->bind.bind) {
							ERROR("bind");
						} else {
							ERROR("rebase target: ", (uintptr_t)chain->rebase.target, " high8: ", (uintptr_t)chain->rebase.high8, " reserved: ", (uintptr_t)chain->rebase.reserved, " next: ", (uintptr_t)chain->rebase.next, " bind: ", (uintptr_t)chain->rebase.bind);
						}
						if (chain->bind.next == 0) {
							break;
						}
						chain += chain->bind.next;
					}
				}
			}
		}
	}
	size_t phnum = macho_segment_count + 2;
	size_t phoff = ALIGN_UP(info.size, _Alignof(ElfW(Phdr)));
	size_t dynnum = 8;
	size_t dynoff = ALIGN_UP(phoff + phnum * sizeof(ElfW(Phdr)), PAGE_SIZE);
	size_t hashoff = ALIGN_UP(dynoff + dynnum * sizeof(ElfW(Dyn)), _Alignof(uint32_t));
	size_t hashsize = 5 * sizeof(uint32_t);
	size_t symoff = ALIGN_UP(hashoff + hashsize, _Alignof(ElfW(Sym)));
	size_t symnum = 1 + dysymtab->nundefsym + dysymtab->nextdefsym;
	size_t stroff = symoff + symnum * sizeof(ElfW(Sym));
	size_t strsize = symtab->strsize;
	size_t relaoff = ALIGN_UP(stroff + strsize, _Alignof(ElfW(Rela)));
	size_t relasize = dysymtab->nlocrel * sizeof(ElfW(Rela));
	size_t new_size = relaoff + relasize;
	ERROR("dysymtab->nlocrel: ", dysymtab->nlocrel);
	ERROR("dysymtab->nextrel: ", dysymtab->nextrel);
	// create output file
	int fd2 = fs_open(argv[2], O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0755);
	if (fd2 < 0) {
		DIE("failed to open ", argv[2], ": ", fs_strerror(fd2));
	}
	result = fs_ftruncate(fd2, new_size);
	if (result < 0) {
		DIE("failed to truncate ", argv[2], ": ", fs_strerror(fd2));
	}
	// map output file
	void *mapping = fs_mmap(NULL, new_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FILE, fd2, 0);
	if (fs_is_map_failed(mapping)) {
		DIE("failed to map ", argv[2], ": ", fs_strerror((intptr_t)mapping));
	}
	// translate macho sections into ELF program headers
	offset = sizeof(struct mach_header_64);
	ElfW(Phdr) *phdr = mapping + phoff;
	size_t last_address = 0;
	for (size_t i = 0; i < load_command_count; i++) {
		const some_load_command *lc = info.base + offset;
		if (lc->command.cmd == LC_SEGMENT_64) {
			*phdr++ = (ElfW(Phdr)) {
				.p_type = PT_LOAD,
				.p_offset = lc->segment.fileoff,
				.p_vaddr = lc->segment.vmaddr - macho_address_base,
				.p_paddr = 0,
				.p_filesz = lc->segment.filesize,
				.p_memsz = lc->segment.vmsize,
				.p_flags = translate_vm_prot(lc->segment.initprot),
				.p_align = 0x10000,
			};
			size_t end = lc->segment.vmaddr - macho_address_base + lc->segment.vmsize;
			if (end > last_address) {
				last_address = end;
			}
		}
		offset += (lc->command.cmdsize + 0x7) & ~0x7;
	}
	*phdr++ = (ElfW(Phdr)) {
		.p_type = PT_LOAD,
		.p_offset = dynoff,
		.p_vaddr = ALIGN_UP(last_address, PAGE_SIZE),
		.p_paddr = ALIGN_UP(last_address, PAGE_SIZE),
		.p_filesz = new_size - dynoff,
		.p_memsz = new_size - dynoff,
		.p_flags = PF_R | PF_W,
		.p_align = PAGE_SIZE,
	};
	*phdr++ = (ElfW(Phdr)) {
		.p_type = PT_DYNAMIC,
		.p_offset = dynoff,
		.p_vaddr = ALIGN_UP(last_address, PAGE_SIZE),
		.p_paddr = ALIGN_UP(last_address, PAGE_SIZE),
		.p_filesz = dynnum * sizeof(ElfW(Dyn)),
		.p_memsz = dynnum * sizeof(ElfW(Dyn)),
		.p_flags = PF_R | PF_W,
		.p_align = _Alignof(ElfW(Dyn)),
	};
	// write ELF dynamic section
	ssize_t trailer_address_offset = ALIGN_UP(last_address, PAGE_SIZE) - dynoff;
	ElfW(Dyn) *dyn = mapping + dynoff;
	*dyn++ = (ElfW(Dyn)) {
		.d_tag = DT_HASH,
		.d_un = {
			.d_ptr = hashoff + trailer_address_offset,
		},
	};
	*dyn++ = (ElfW(Dyn)) {
		.d_tag = DT_STRTAB,
		.d_un = {
			.d_ptr = stroff + trailer_address_offset,
		},
	};
	*dyn++ = (ElfW(Dyn)) {
		.d_tag = DT_SYMTAB,
		.d_un = {
			.d_ptr = symoff + trailer_address_offset,
		},
	};
	*dyn++ = (ElfW(Dyn)) {
		.d_tag = DT_RELA,
		.d_un = {
			.d_ptr = relaoff + trailer_address_offset,
		},
	};
	*dyn++ = (ElfW(Dyn)) {
		.d_tag = DT_RELASZ,
		.d_un = {
			.d_val = relasize,
		},
	};
	*dyn++ = (ElfW(Dyn)) {
		.d_tag = DT_RELAENT,
		.d_un = {
			.d_val = sizeof(ElfW(Rela)),
		},
	};
	*dyn++ = (ElfW(Dyn)) {
		.d_tag = DT_STRSZ,
		.d_un = {
			.d_val = strsize,
		},
	};
	*dyn++ = (ElfW(Dyn)) {
		.d_tag = DT_SYMENT,
		.d_un = {
			.d_val = sizeof(ElfW(Sym)),
		},
	};
	*dyn++ = (ElfW(Dyn)) {
		.d_tag = DT_NULL,
	};
	// write symbol table header
	uint32_t *hash = mapping + hashoff;
	*hash++ = 1; // nbucket
	*hash++ = symnum; // nchain
	*hash++ = 0; // bucket[0]
	for (int i = 1; i < symnum; i++) {
		*hash++ = i; // chain[i-1]
	}
	*hash++ = 0; // chain[i]
	// write symbol table
	ElfW(Sym) *sym = mapping + symoff;
	*sym++ = (ElfW(Sym)) {
		.st_name = 0,
		.st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE),
		.st_shndx = SHN_UNDEF,
		.st_other = STV_DEFAULT,
		.st_value = 0,
		.st_size = 0,
	};
	const struct nlist_64 *nlist = info.base + symtab->symoff;
	// write undefined symbols
	const struct nlist_64 *undef_sym = &nlist[dysymtab->iundefsym];
	for (size_t i = 0; i < dysymtab->nundefsym; i++) {
		*sym++ = (ElfW(Sym)) {
			.st_name = undef_sym[i].n_un.n_strx,
			.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC),
			.st_shndx = SHN_UNDEF,
			.st_other = STV_DEFAULT,
			.st_value = 0,
			.st_size = 0,
		};
	}
	// write defined symbols
	const struct nlist_64 *external_sym = &nlist[dysymtab->iextdefsym];
	for (size_t i = 0; i < dysymtab->nextdefsym; i++) {
		*sym++ = (ElfW(Sym)) {
			.st_name = external_sym[i].n_un.n_strx,
			.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC),
			.st_shndx = 1,
			.st_other = STV_DEFAULT,
			.st_value = external_sym[i].n_value == 0 ? 0 : external_sym[i].n_value - macho_address_base,
			.st_size = 0,
		};
	}
	// write strings
	fs_memcpy(mapping + stroff, info.base + symtab->stroff, symtab->strsize);
	// write relocations
	// write ELF header
	fs_memcpy(mapping, info.base, info.size);
	ElfW(Ehdr) *header = mapping;
	header->e_ident[EI_MAG0] = ELFMAG0;
	header->e_ident[EI_MAG1] = ELFMAG1;
	header->e_ident[EI_MAG2] = ELFMAG2;
	header->e_ident[EI_MAG3] = ELFMAG3;
	header->e_ident[EI_CLASS] = ELFCLASS64;
	header->e_ident[EI_DATA] = ELFDATA2LSB;
	header->e_ident[EI_VERSION] = EV_CURRENT;
	header->e_ident[EI_OSABI] = ELFOSABI_LINUX;
	header->e_ident[EI_ABIVERSION] = 0;
	header->e_ident[EI_ABIVERSION] = 0;
	fs_memset(&header->e_ident[EI_PAD], '\0', sizeof(sizeof(header->e_ident)) - EI_PAD);
	header->e_ident[EI_NIDENT] = sizeof(header->e_ident);
	header->e_type = ET_DYN;
	header->e_machine = CURRENT_ELF_MACHINE;
	header->e_version = EV_CURRENT;
	header->e_entry = 0;
	header->e_phoff = phoff;
	header->e_shoff = 0;
	header->e_flags = 0;
	header->e_ehsize = sizeof(ElfW(Ehdr));
	header->e_phentsize = sizeof(ElfW(Phdr));
	header->e_phnum = phnum;
	header->e_shentsize = sizeof(ElfW(Shdr));
	header->e_shnum = 0;
	header->e_shstrndx = SHN_UNDEF;
	fs_close(fd2);
	return 0;
}
#pragma GCC pop_options
