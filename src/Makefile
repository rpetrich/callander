NATIVEMACHINE ?= $(shell uname -m)
ifeq ($(NATIVEMACHINE),arm64)
	NATIVEMACHINE = aarch64
endif
TARGETMACHINE ?= $(shell uname -m)
ifeq ($(TARGETMACHINE),arm64)
	TARGETMACHINE = aarch64
endif
TARGETOS ?= linux

ifneq ($(TARGETMACHINE),i386)
	CFLAGS=
ifeq ($(TARGETOS),linux)
	LDFLAGS=-Wl,-z,combreloc -Wl,-z,relro
else
	LDFLAGS=
endif
	BASE_ADDRESS=0x200000
ifeq ($(TARGETMACHINE),x86_64)
	CFLAGS+=-mno-red-zone -mfsgsbase -mgeneral-regs-only
	LDFLAGS+=-mfsgsbase
endif
else
	CFLAGS=-m32
	LDFLAGS=-m32
	BASE_ADDRESS=0x08040000
endif

ifeq ($(TARGETOS),windows)
	CC = $(TARGETMACHINE)-w64-mingw32-gcc
	LDFLAGS += -lsynchronization -lws2_32
	BINSUFFIX := .exe
else
ifneq ($(NATIVEMACHINE),$(TARGETMACHINE))
	CC = $(TARGETMACHINE)-$(TARGETOS)-gnu-gcc
	export PATH := /usr/$(TARGETMACHINE)-$(TARGETOS)-gnu/bin:$(PATH)
endif
	BINSUFFIX :=
endif
OBJCOPY ?= objcopy
STRIP ?= strip

CFLAGS += -DPRODUCT_NAME='"callander"' -DLIBZIP_MINIMAL

CFLAGS += -fvisibility=hidden -ffunction-sections -fdata-sections
LDFLAGS += -fvisibility=hidden
ifeq ($(TARGETOS),linux)
	CFLAGS += -flto -freorder-blocks-and-partition -D HAVE_UNISTD_H=1 -D HAVE_STDARG_H=1
	LDFLAGS += -flto -Wl,--gc-sections -freorder-blocks-and-partition
	STANDALONE ?= 1
	DEBUG_FLAGS := -gdwarf-2 -g1 -ggdb
else
	STANDALONE ?= 0
	CFLAGS += -Wno-inline-asm
ifeq ($(TARGETOS),darwin)
	DEBUG_FLAGS := -glldb -fno-standalone-debug
else
	DEBUG_FLAGS := -g
endif
endif

# record stack usage to objs-*/*.su
# CFLAGS += -fstack-usage
# LDFLAGS += -fstack-usage

CFLAGS += -isystem system -I libzip -I zlib -fno-omit-frame-pointer -Werror -Wall -Wextra -Wno-missing-braces -Wuninitialized -Wunused-parameter -Wtype-limits -Wsign-compare -Wimplicit-fallthrough -Wdouble-promotion -Wundef -fcf-protection=none
ifeq ($(STANDALONE),1)
	CFLAGS += -fno-asynchronous-unwind-tables
endif
ifeq ($(shell $(CC) --version | grep -o 'Free Software Foundation'),Free Software Foundation)
	# cannot use floating point registers in trap handlers!
	# CFLAGS += -mgeneral-regs-only
	CFLAGS += -Wold-style-declaration -Wmissing-parameter-type
ifeq ($(TARGETMACHINE),aarch64)
	CFLAGS += -Wno-maybe-uninitialized
endif
else
ifeq ($(CC),clang)
ifeq ($(TARGETMACHINE),aarch64)
	CFLAGS += -mgeneral-regs-only
else
	CFLAGS += -mno-sse
endif
endif
CFLAGS += -Wno-gnu-null-pointer-arithmetic -Wno-unused-but-set-variable -Wno-tautological-unsigned-enum-zero-compare
endif

ifeq ($(TARGETMACHINE),aarch64)
	CFLAGS += -Wno-psabi -march=armv8-a+lse
	LDFLAGS += -Wno-psabi -march=armv8-a+lse
endif

PERMISSIVE_CFLAGS := -Wno-unused-parameter -Wno-strict-aliasing -Wno-int-in-bool-context -Wno-implicit-fallthrough -Wno-sign-compare -Wno-double-promotion -Wno-format

ifeq ($(COVERAGE),1)
	CFLAGS += --coverage -DCOVERAGE=1 -fprofile-arcs -ftest-coverage
endif

ifeq ($(STACK_PROTECTOR),1)
	CFLAGS += -fstack-protector -DSTACK_PROTECTOR=1
else
	CFLAGS += -fno-stack-protector
endif

ifeq ($(ADDRESS_SANITIZER),1)
	CFLAGS += -fsanitize=address -static-libasan
endif

ifeq ($(UNDEFINED_SANITIZER),1)
	CFLAGS += -fsanitize=undefined -static-libubsan
	LDFLAGS += -fsanitize=undefined -static-libubsan
endif

ifeq ($(ANALYZER),1)
	CFLAGS += -fanalyzer
endif

ifeq ($(TARGETMACHINE),aarch64)
	ARCH_SOURCES := arch-arm64/disassembler/decode.c arch-arm64/disassembler/decode0.c \
			arch-arm64/disassembler/decode1.c arch-arm64/disassembler/decode2.c \
			arch-arm64/disassembler/decode_scratchpad.c arch-arm64/disassembler/encodings_dec.c \
			arch-arm64/disassembler/pcode.c arch-arm64/disassembler/decode_fields32.c \
			arch-arm64/disassembler/sysregs_fmt_gen.c arch-arm64/disassembler/sysregs_gen.c \
			arch-arm64/disassembler/operations.c arch-arm64/disassembler/format.c \
			arch-arm64/disassembler/regs.c \
			printf.c printf_inject.c callander_aarch64.c
	PATCH_SOURCES := patch.c patch_aarch64.c
endif
ifeq ($(TARGETMACHINE),x86_64)
	ARCH_SOURCES += x86.c x86_64_length_disassembler.c callander_x86_64.c
	PATCH_SOURCES := patch.c patch_x86_64.c
endif

COMMON_CALLANDER_SOURCES := callander.c callander_print.c defaultlibs.c loader.c \
			mapped.c qsort.c search.c $(ARCH_SOURCES)
ifeq ($(TARGETOS),linux)
	COMMON_CALLANDER_SOURCES += bpf_debug.c
endif
ifeq ($(STANDALONE),1)
	CFLAGS += -DSTANDALONE=1
	COMMON_SOURCES := errbuf.c malloc.c
else
	COMMON_SOURCES := errbuf.c
endif

AXON_COMMON_SOURCES := $(COMMON_SOURCES) $(PATCH_SOURCES) $(ARCH_SOURCES) attempt.c axon.c coverage.c \
			debugger.c defaultlibs.c exec.c fd_table.c fork.c install.c intercept.c \
			handler.c libraries.c loader.c mapped.c preload.c qsort.c remote.c \
			remote_library.c resolver.c search.c seccomp.c sockets.c stack.c time.c tls.c tracer.c \
			vfs.c vfs_local.c callander_print.c axon_shared.c
AXON_SOURCES := $(AXON_COMMON_SOURCES) darwin.c paths.c proxy.c vfs_linux.c vfs_darwin.c vfs_windows.c windows.c
TEXEC_SOURCES := $(COMMON_SOURCES) $(PATCH_SOURCES) $(ARCH_SOURCES) attempt.c darwin.c \
			defaultlibs.c exec.c fd_table.c loader.c proxy.c qsort.c remote.c remote_exec.c search.c seccomp.c \
		    stack.c texec.c time.c tls.c windows.c x86.c callander.c callander_print.c axon_shared.c
THANDLER_SOURCES := $(COMMON_SOURCES) attempt_target.c darwin.c defaultlibs.c exec_target.c \
			fd_table_target.c fork_target.c handler.c intercept_target.c malloc.c paths_target.c \
			proxy_target.c remote.c remote_library_target.c sockets_target.c stack.c thandler.c \
			tls.c tracer.c vfs.c vfs_local.c vfs_linux.c callander_print.c axon_shared.c
LIBZIP_SOURCES := libzip/lib/zip_buffer.c libzip/lib/zip_error.c libzip/lib/zip_error_clear.c libzip/lib/zip_error_get.c libzip/lib/zip_error_get_sys_type.c libzip/lib/zip_error_strerror.c libzip/lib/zip_error_to_str.c libzip/lib/zip_extra_field.c libzip/lib/zip_extra_field_api.c libzip/lib/zip_file_error_clear.c libzip/lib/zip_file_error_get.c libzip/lib/zip_file_get_comment.c libzip/lib/zip_file_get_external_attributes.c libzip/lib/zip_file_get_offset.c libzip/lib/zip_file_strerror.c libzip/lib/zip_fseek.c libzip/lib/zip_ftell.c libzip/lib/zip_get_archive_flag.c libzip/lib/zip_get_file_comment.c libzip/lib/zip_get_name.c libzip/lib/zip_get_num_entries.c libzip/lib/zip_get_num_files.c libzip/lib/zip_hash.c libzip/lib/zip_io_util.c libzip/lib/zip_libzip_version.c libzip/lib/zip_memdup.c libzip/lib/zip_name_locate.c libzip/lib/zip_new.c libzip/lib/zip_pkware.c libzip/lib/zip_realloc.c libzip/lib/zip_source_accept_empty.c libzip/lib/zip_source_buffer.c libzip/lib/zip_source_call.c libzip/lib/zip_source_close.c libzip/lib/zip_source_error.c libzip/lib/zip_source_file_common.c libzip/lib/zip_source_free.c libzip/lib/zip_source_function.c libzip/lib/zip_source_get_dostime.c libzip/lib/zip_source_get_file_attributes.c libzip/lib/zip_source_layered.c libzip/lib/zip_source_open.c libzip/lib/zip_source_pass_to_lower_layer.c libzip/lib/zip_source_pkware_decode.c libzip/lib/zip_source_read.c libzip/lib/zip_source_seek.c libzip/lib/zip_source_seek_write.c libzip/lib/zip_source_stat.c libzip/lib/zip_source_supports.c libzip/lib/zip_source_tell.c libzip/lib/zip_source_tell_write.c libzip/lib/zip_source_window.c libzip/lib/zip_source_write.c libzip/lib/zip_stat.c libzip/lib/zip_stat_index.c libzip/lib/zip_stat_init.c libzip/lib/zip_strerror.c libzip/lib/zip_string.c libzip/lib/zip_open.c libzip/lib/zip_dirent.c libzip/lib/zip_entry.c libzip/lib/zip_discard.c
ZAXON_SOURCES := $(COMMON_SOURCES) $(AXON_COMMON_SOURCES) proxy_zaxon.c vfs_zip.c mktime.c $(LIBZIP_SOURCES) zlib/inflate.c zlib/crc32.c zlib/inftrees.c zlib/adler32.c zlib/inffast.c
LOOKUP_SOURCES := $(COMMON_SOURCES) defaultlibs.c loader.c lookup_main.c resolver.c
LIBCALLBOX_SOURCES := $(COMMON_SOURCES) $(ARCH_SOURCES) $(PATCH_SOURCES) \
			$(COMMON_CALLANDER_SOURCES) callander_seccomp.c libcallbox.c attempt.c defaultlibs.c loader.c mapped.c \
			proxy.c tls.c axon_shared.c
CALLANDER_SOURCES := $(COMMON_SOURCES) $(COMMON_CALLANDER_SOURCES) callander_seccomp.c callander_main.c
LIBCALLANDER_SOURCES := $(COMMON_SOURCES) $(COMMON_CALLANDER_SOURCES) callander_seccomp.c libcallander.c
LEXEC_SOURCES := ${COMMON_SOURCES} $(COMMON_CALLANDER_SOURCES) $(PATCH_SOURCES) lexec.c remote_exec.c tls.c attempt.c stack.c
LD_REL_SOURCES := loader.c ld_rel.c defaultlibs.c malloc.c
SMOOSH_SOURCES := $(COMMON_SOURCES) $(COMMON_CALLANDER_SOURCES) smoosh.c debugger.c
MACHO_TO_ELF_SOURCES := $(COMMON_SOURCES) defaultlibs.c loader.c macho_to_elf.c macho.c

ifeq ($(TARGETOS),linux)
CALLANDER_OPT := -Os -ftree-vectorize \
	-fauto-inc-dec -fbranch-count-reg -fcombine-stack-adjustments -fcompare-elim -fcprop-registers -fdce -fdefer-pop -fdse -fforward-propagate -fguess-branch-probability -fif-conversion -fif-conversion2 -finline-functions-called-once -fipa-profile -fipa-pure-const -fipa-reference -fipa-reference-addressable -fmerge-constants -fmove-loop-invariants -freorder-blocks -fshrink-wrap -fshrink-wrap-separate -fsplit-wide-types -fssa-backprop -fssa-phiopt -ftree-bit-ccp -ftree-ccp -ftree-ch -ftree-coalesce-vars -ftree-copy-prop -ftree-dce -ftree-dominator-opts -ftree-dse -ftree-forwprop -ftree-fre -ftree-phiprop -ftree-pta -ftree-scev-cprop -ftree-sink -ftree-slsr -ftree-sra -ftree-ter -funit-at-a-time \
	-falign-functions -falign-jumps -falign-labels -falign-loops -fcaller-saves -fcode-hoisting -fcrossjumping -fcse-follow-jumps -fcse-skip-blocks -fdelete-null-pointer-checks -fdevirtualize -fdevirtualize-speculatively -fexpensive-optimizations -fgcse -fgcse-lm -fhoist-adjacent-loads -finline-small-functions -findirect-inlining -fipa-bit-cp -fipa-cp -fipa-icf -fipa-ra -fipa-sra -fipa-vrp -fisolate-erroneous-paths-dereference -flra-remat -foptimize-sibling-calls -foptimize-strlen -fpartial-inlining -fpeephole2 -freorder-blocks-algorithm=stc -freorder-blocks-and-partition -freorder-functions -frerun-cse-after-loop -fschedule-insns -fschedule-insns2 -fsched-interblock -fsched-spec -fstore-merging -fstrict-aliasing -fthread-jumps -ftree-builtin-call-dce -ftree-pre -ftree-switch-conversion -ftree-tail-merge -ftree-vrp
CALLANDER_OPT := -Os
else
CALLANDER_OPT := -O2
endif

objdir = .objs-$(TARGETOS)-$(TARGETMACHINE)

.PHONY: all test test-debug test-trace clean install

all: axon zaxon tests/sample tests/sample_fs tests/sample_fs_pie tests/sample_write tests/sample_dyn tests/sigsys_receive tests/fault tests/segfault target target2 target3 texec thandler callander lookup libcallbox.so libcallander.so

test: all
	./compare.sh tests/sigsys_receive || exit 1
	./compare.sh tests/sample_fs || exit 1
	./compare.sh tests/sample || exit 1
	./compare.sh tests/sample_dyn || exit 1
	./compare.sh echo hi || exit 1
	./compare.sh bash -c 'echo hi' || exit 1
	./compare.sh tests/script.sh || exit 1
	./compare.sh tests/fault || exit 1
	./compare.sh tests/segfault || exit 1
	./compare.sh ls -lah /proc/self/exe || exit 1

test-debug: all
	AXON_ADDR=$(BASE_ADDRESS) gdb --args ./axon tests/sample_fs

test-trace: all
	strace -f ./axon tests/sample_fs

clean:
	rm -f axon texec thandler target target2 target3 callander libcallander.so libcallbox.so lookup *.debug *.gcno *.gcov *.gcda tests/sample tests/sample_fs tests/sample_fs_pie tests/sample_write tests/sample_dyn tests/sigsys_receive tests/fault tests/segfault
	rm -rf "$(objdir)"

$(objdir)/%.o: %.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -fstack-usage -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) -Os -o "$@" -c "$<"

$(objdir)/libzip/%.o: libzip/%.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) $(PERMISSIVE_CFLAGS) -DZIP_EXTERN= -Dmalloc=shared_malloc -Dfree=shared_free -Drealloc=shared_realloc -Dcalloc=shared_calloc -fstack-usage -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) -Os -o "$@" -c "$<"

$(objdir)/zlib/%.o: zlib/%.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -fstack-usage -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) -O2 -o "$@" -c "$<"

$(objdir)/arch-arm64/disassembler/%.o: arch-arm64/disassembler/%.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) $(PERMISSIVE_CFLAGS) -Wno-unused-function -fstack-usage -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) -Os -o "$@" -c "$<"

$(objdir)/defaultlibs.o: defaultlibs.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -fstack-usage -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) -O2 -o "$@" -c "$<"

$(objdir)/callander.o: callander.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) $(CALLANDER_OPT) -o "$@" -c "$<"

ifeq ($(TARGETOS),linux)
$(objdir)/target.o: callander.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) -Oz -fno-toplevel-reorder -o "$@" -c "$<"
endif

$(objdir)/malloc.o: malloc.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) -Os -DHAVE_MORECORE=0 -DHAVE_MMAP=1 -DMSPACES=1 -DUSE_DL_PREFIX=1 -DNO_MALLOC_STATS=1 -DUSE_LOCKS=0 '-DMALLOC_FAILURE_ACTION=abort();' -DLACKS_TIME_H -DHAVE_MREMAP=0 '-DDLMALLOC_EXPORT=__attribute__((visibility("hidden")))' -include axon.h -Dmalloc_getpagesize=PAGE_SIZE -o "$@" -c "$<"

axon: $(foreach obj,$(AXON_SOURCES:.c=.o),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) -Wno-lto-type-mismatch -Wl,--exclude-libs,ALL -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $(DEBUG_FLAGS) $^ -o "$@"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

zaxon: $(foreach obj,$(ZAXON_SOURCES:.c=.o),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) -Wno-lto-type-mismatch -Wl,--exclude-libs,ALL -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $(DEBUG_FLAGS) $^ -o "$@"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

install: axon libaxon.so ld.so.preload
	mkdir -p /bin
	cp -a axon /bin/
	mkdir -p /etc
	cp -a ld.so.preload /etc/

lookup: $(foreach obj,$(LOOKUP_SOURCES:.c=.o),$(objdir)/$(obj))
ifeq ($(STANDALONE),1)
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g3 $^ -o "$@"
else
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

tests/sample: tests/sample.c *.h Makefile
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -static -no-pie -ffreestanding -o "$@" "$<"

tests/sample_dyn: tests/sample.c *.h Makefile
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -o "$@" "$<"

tests/sample_fs: tests/sample_fs.c *.h Makefile
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -static -nostdlib -no-pie -O2 -ffreestanding -Wl,-e,impulse -o "$@" "$<"

tests/sample_fs_pie: tests/sample_fs.c *.h Makefile
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -nostdlib -pie -fPIC -O2 -ffreestanding -Wl,-e,impulse -o "$@" "$<"

tests/sample_write: tests/sample_write.c *.h Makefile
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -nostdlib -fPIC -O2  -nostdlib -shared -nostartfiles -ffreestanding -Wl,-e,impulse -o "$@" "$<"

tests/sigsys_receive: tests/sigsys_receive.c Makefile
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -static -no-pie -ffreestanding -o "$@" "$<"

tests/fault: tests/fault.c *.h Makefile
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -static -no-pie -ffreestanding -o "$@" "$<"

tests/segfault: tests/segfault.c *.h Makefile
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -static -no-pie -ffreestanding -o "$@" "$<"

# full axon target payload
target$(BINSUFFIX): target.c *.h Makefile
ifeq ($(TARGETOS),linux)
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -nostdlib -shared -nostartfiles -ffreestanding -fPIC -Os -ffreestanding -Wl,-e,release -Wl,--build-id=none -Wl,--no-dynamic-linker -fcf-protection=none -fno-asynchronous-unwind-tables  -fno-toplevel-reorder -o "$@" "$<"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"
else
	$(CC) $(DEBUG_FLAGS) -o "$@" "$<" $(LDFLAGS)
endif

# basic remote shell payload
target2$(BINSUFFIX): target2.c *.h Makefile
ifeq ($(TARGETOS),linux)
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUG_FLAGS) -nostdlib -shared -nostartfiles -ffreestanding -fPIC -Os -ffreestanding -Wl,-e,release -Wl,--build-id=none -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -fcf-protection=none -fno-asynchronous-unwind-tables  -fno-toplevel-reorder -o "$@" "$<"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"
else
	$(CC) $(DEBUG_FLAGS) -o "$@" "$<" $(LDFLAGS)
endif

# intermediary payload
target3$(BINSUFFIX): target3.c *.h Makefile
ifeq ($(TARGETOS),linux)
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -nostdlib -shared -nostartfiles -ffreestanding -fPIC -Os -ffreestanding -Wl,-e,release -Wl,--build-id=none -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -fcf-protection=none -fno-asynchronous-unwind-tables  -fno-toplevel-reorder -o "$@" "$<"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"
else
	$(CC) $(DEBUG_FLAGS) -o "$@" "$<" $(LDFLAGS)
endif

# executes binaries remotely
texec: $(foreach obj,$(TEXEC_SOURCES:.c=.o),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

# payload for executing binaries remotely
thandler: $(foreach obj,$(THANDLER_SOURCES:.c=.o),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

callander_$(TARGETMACHINE): $(foreach obj,$(CALLANDER_SOURCES:.c=.o),$(objdir)/$(obj))
ifeq ($(STANDALONE),1)
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
else
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

callander: callander_$(TARGETMACHINE)
	rm -rf "$@" "$@.debug"
	ln callander_$(TARGETMACHINE) "$@.debug" || cp -a callander_$(NATIVEMACHINE) "$@.debug"
	ln callander_$(TARGETMACHINE) "$@" || cp -a callander_$(NATIVEMACHINE) "$@"

ld-rel.so: $(foreach obj,$(LD_REL_SOURCES:.c=.o),$(objdir)/$(obj))
ifeq ($(STANDALONE),1)
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
else
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

smoosh: $(foreach obj,$(SMOOSH_SOURCES:.c=.o),$(objdir)/$(obj))
ifeq ($(STANDALONE),1)
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
else
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

macho_to_elf: $(foreach obj,$(MACHO_TO_ELF_SOURCES:.c=.o),$(objdir)/$(obj))
ifeq ($(STANDALONE),1)
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
else
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

libcallander.so: $(foreach obj,$(LIBCALLANDER_SOURCES:.c=.o),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"

libcallbox.so: $(foreach obj,$(LIBCALLBOX_SOURCES:.c=.o),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"

callander_test: $(foreach obj,$(LIBCALLANDER_SOURCES:.c=.o) callander_test_main.c,$(objdir)/$(obj))
ifeq ($(STANDALONE),1)
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
else
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

lexec: $(foreach obj,$(LEXEC_SOURCES:.c=.o),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -fPIE $^ -o "$@"
# 	codesign -s gdb_codesign -o runtime --entitlements entitlements.xml "$@"

systranslate: systranslate.c defaultlibs.c syscall_defs_x86_64.h Makefile
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -o "$@" "$<" defaultlibs.c
