#include "macho.h"

#include "axon.h"
#include "freestanding.h"

#include <mach-o/fat.h>

__attribute__((warn_unused_result)) int load_macho_binary(int fd, struct macho_binary_info *out_info)
{
	struct fs_stat stat;
	int result = fs_fstat(fd, &stat);
	if (result < 0) {
		ERROR("could not stat binary: ", fs_strerror(result));
		return -ENOEXEC;
	}

	void *base = fs_mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (fs_is_map_failed(base)) {
		ERROR("could not mmap binary: ", fs_strerror((intptr_t)base));
	}

	void *slice_base = base;
	size_t slice_size = stat.st_size;

	const struct fat_header *fat_header = base;
	if (fat_header->magic == FAT_CIGAM) {
		const struct fat_arch *arch = base + sizeof(*fat_header);
		size_t narch = __builtin_bswap32(fat_header->nfat_arch);
		for (int i = 0; i < narch; i++) {
			ERROR("cputype: ", (uintptr_t)arch[i].cputype, " cpusubtype: ", (uintptr_t)arch[i].cpusubtype);
			if (__builtin_bswap32(arch[i].cputype) == CPU_TYPE_ARM64) {
				ERROR("found arm64 at ", __builtin_bswap32(arch[i].offset));
				slice_base = base + __builtin_bswap32(arch[i].offset);
				slice_size = __builtin_bswap32(arch[i].size);
				break;
			}
		}
	}

	const struct mach_header_64 *header = slice_base;
	if (header->magic != MH_MAGIC_64) {
		ERROR("missing magic: ", (uintptr_t)header->magic);
		fs_munmap(base, stat.st_size);
		return -ENOEXEC;
	}

	size_t load_command_count = header->ncmds;
	ERROR("load commands: ", (intptr_t)load_command_count);
	size_t offset = sizeof(*header);
	for (size_t i = 0; i < load_command_count; i++) {
		const some_load_command *lc = slice_base + offset;
		ERROR("load command: ", (uintptr_t)lc->command.cmd, " of size ", (intptr_t)lc->command.cmdsize);
		switch (lc->command.cmd) {
		case LC_SEGMENT:
			ERROR("segment");
			break;
		case LC_SYMTAB:
			ERROR("symbol table");
			break;
		case LC_SYMSEG:
			ERROR("symbol segment");
			break;
		case LC_THREAD:
			ERROR("thread info");
			break;
		case LC_UNIXTHREAD:
			ERROR("unix thread info");
			break;
		case LC_LOADFVMLIB:
			ERROR("load fvmlib");
			break;
		case LC_IDFVMLIB:
			ERROR("id fvmlib");
			break;
		case LC_IDENT:
			ERROR("ident");
			break;
		case LC_FVMFILE:
			ERROR("fvm file");
			break;
		case LC_PREPAGE:
			ERROR("prepage");
			break;
		case LC_DYSYMTAB:
			ERROR("dynamic symbol table");
			break;
		case LC_LOAD_DYLIB:
			ERROR("load dylib: ", (const char *)slice_base + offset + lc->dylib.dylib.name.offset);
			break;
		case LC_ID_DYLIB:
			ERROR("id dylib");
			break;
		case LC_LOAD_DYLINKER:
			ERROR("load dylinker");
			break;
		case LC_ID_DYLINKER:
			ERROR("id dylinker");
			break;
		case LC_PREBOUND_DYLIB:
			ERROR("prebound dylib");
			break;
		case LC_ROUTINES:
			ERROR("routines");
			break;
		case LC_SUB_FRAMEWORK:
			ERROR("subframework");
			break;
		case LC_SUB_UMBRELLA:
			ERROR("subumbrella");
			break;
		case LC_SUB_CLIENT:
			ERROR("subclient");
			break;
		case LC_SUB_LIBRARY:
			ERROR("sublibrary");
			break;
		case LC_TWOLEVEL_HINTS:
			ERROR("two level hints");
			break;
		case LC_PREBIND_CKSUM:
			ERROR("prebind checksum");
			break;
		case LC_LOAD_WEAK_DYLIB:
			ERROR("load weak dylib");
			break;
		case LC_SEGMENT_64:
			ERROR("segment 64: ", lc->segment.segname);
			break;
		case LC_ROUTINES_64:
			ERROR("routines 64");
			break;
		case LC_UUID:
			ERROR("uuid");
			break;
		case LC_RPATH:
			ERROR("rpath");
			break;
		case LC_CODE_SIGNATURE:
			ERROR("code signature");
			break;
		case LC_SEGMENT_SPLIT_INFO:
			ERROR("segment split info");
			break;
		case LC_REEXPORT_DYLIB:
			ERROR("reexport dylib");
			break;
		case LC_LAZY_LOAD_DYLIB:
			ERROR("lazy load dylib");
			break;
		case LC_ENCRYPTION_INFO:
			ERROR("encryption info");
			break;
		case LC_DYLD_INFO:
			ERROR("dylc info");
			break;
		case LC_DYLD_INFO_ONLY:
			ERROR("dyld info only");
			break;
		case LC_LOAD_UPWARD_DYLIB:
			ERROR("load upward dylib");
			break;
		case LC_VERSION_MIN_MACOSX:
			ERROR("min macos");
			break;
		case LC_VERSION_MIN_IPHONEOS:
			ERROR("min ios");
			break;
		case LC_FUNCTION_STARTS:
			ERROR("function starts");
			break;
		case LC_DYLD_ENVIRONMENT:
			ERROR("dyld environment");
			break;
		case LC_MAIN:
			ERROR("main");
			break;
		case LC_DATA_IN_CODE:
			ERROR("data in code");
			break;
		case LC_SOURCE_VERSION:
			ERROR("source version");
			break;
		case LC_DYLIB_CODE_SIGN_DRS:
			ERROR("dylib code sign dirs");
			break;
		case LC_ENCRYPTION_INFO_64:
			ERROR("encryption info 64");
			break;
		case LC_LINKER_OPTION:
			ERROR("linker option");
			break;
		case LC_LINKER_OPTIMIZATION_HINT:
			ERROR("linker optimization hint");
			break;
		case LC_VERSION_MIN_TVOS:
			ERROR("version min tvos");
			break;
		case LC_VERSION_MIN_WATCHOS:
			ERROR("version min watchos");
			break;
		case LC_NOTE:
			ERROR("note");
			break;
		case LC_BUILD_VERSION:
			ERROR("build version");
			break;
		case LC_DYLD_EXPORTS_TRIE:
			ERROR("dyld exports trie");
			break;
		case LC_DYLD_CHAINED_FIXUPS:
			ERROR("dyld chained fixups");
			break;
		default:
			ERROR("unknown load command");
			break;
		}
		// offset += sizeof(*lc);
		offset += (lc->command.cmdsize + 0x7) & ~0x7;
		ERROR_FLUSH();
	}

	out_info->base = slice_base;
	out_info->size = slice_size;
	out_info->fat_base = base;
	out_info->fat_size = stat.st_size;
	return 0;
}

void unload_macho_binary(struct macho_binary_info *info)
{
	fs_munmap(info->base, info->size);
}
