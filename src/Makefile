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

CFLAGS += -DPRODUCT_NAME='"callander"'

CFLAGS += -fvisibility=hidden -ffunction-sections -fdata-sections
LDFLAGS += -fvisibility=hidden
ifeq ($(TARGETOS),linux)
	CFLAGS += -flto
	LDFLAGS += -flto -Wl,--gc-sections
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

CFLAGS += -fno-omit-frame-pointer -fno-asynchronous-unwind-tables -Werror -Wall -Wextra -Wno-missing-braces -Wuninitialized -Wunused-parameter -Wtype-limits -Wsign-compare -Wimplicit-fallthrough -Wdouble-promotion -Wundef -fcf-protection=none
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
	CFLAGS += -Wno-unused-function -Wno-unused-parameter -Wno-strict-aliasing -Wno-int-in-bool-context -Wno-implicit-fallthrough -Wno-sign-compare -Wno-double-promotion -Wno-format
endif

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
	ARCH_OBJECTS := arch-arm64/disassembler/decode.o arch-arm64/disassembler/decode0.o \
			arch-arm64/disassembler/decode1.o arch-arm64/disassembler/decode2.o \
			arch-arm64/disassembler/decode_scratchpad.o arch-arm64/disassembler/encodings_dec.o \
			arch-arm64/disassembler/pcode.o arch-arm64/disassembler/decode_fields32.o \
			arch-arm64/disassembler/sysregs.o arch-arm64/disassembler/operations.o \
			arch-arm64/disassembler/format.o arch-arm64/disassembler/regs.o \
			printf.o printf_inject.o
	PATCH_OBJECTS := patch.o patch_aarch64.o
endif
ifeq ($(TARGETMACHINE),x86_64)
	ARCH_OBJECTS += x86.o x86_64_length_disassembler.o
	PATCH_OBJECTS := patch.o patch_x86_64.o
endif

COMMON_CALLANDER_OBJECTS := callander.o callander_print.o defaultlibs.o loader.o \
			mapped.o qsort.o search.o $(ARCH_OBJECTS)
ifeq ($(TARGETOS),linux)
	COMMON_CALLANDER_OBJECTS += bpf_debug.o
endif
ifeq ($(STANDALONE),1)
	CFLAGS += -DSTANDALONE=1
	COMMON_OBJECTS := malloc.o
else
	COMMON_OBJECTS :=
endif

OBJECTS :=  $(COMMON_OBJECTS) $(PATCH_OBJECTS) $(ARCH_OBJECTS) attempt.o axon.o coverage.o \
			darwin.o debugger.o defaultlibs.o exec.o fd_table.o fork.o install.o intercept.o \
			handler.o libraries.o loader.o mapped.o paths.o preload.o proxy.o qsort.o remote.o \
			remote_library.o resolver.o search.o seccomp.o sockets.o stack.o time.o tls.o tracer.o \
			vfs.o vfs_darwin.o vfs_local.o vfs_linux.o vfs_windows.o windows.o callander_print.o
TEXEC_OBJECTS := $(COMMON_OBJECTS) $(PATCH_OBJECTS) $(ARCH_OBJECTS) attempt.o darwin.o \
			defaultlibs.o exec.o fd_table.o loader.o proxy.o qsort.o remote.o remote_exec.o search.o seccomp.o \
		    stack.o texec.o time.o tls.o windows.o x86.o callander.o callander_print.o
THANDLER_OBJECTS := $(COMMON_OBJECTS) attempt_target.o darwin.o defaultlibs.o exec_target.o \
			fd_table_target.o fork_target.o handler.o intercept_target.o malloc.o paths_target.o \
			proxy_target.o remote.o remote_library_target.o sockets_target.o stack.o thandler.o \
			tls.o tracer.o vfs.o vfs_local.o vfs_linux.o callander_print.o
LOOKUP_OBJECTS := $(COMMON_OBJECTS) defaultlibs.o loader.o lookup_main.o resolver.o
LIBCALLBOX_OBJECTS := $(COMMON_OBJECTS) $(ARCH_OBJECTS) $(PATCH_OBJECTS) \
			$(COMMON_CALLANDER_OBJECTS) callander_seccomp.o libcallbox.o attempt.o defaultlibs.o loader.o mapped.o \
			proxy.o tls.o
CALLANDER_OBJECTS := $(COMMON_OBJECTS) $(COMMON_CALLANDER_OBJECTS) callander_seccomp.o callander_main.o
LIBCALLANDER_OBJECTS := $(COMMON_OBJECTS) $(COMMON_CALLANDER_OBJECTS) callander_seccomp.o libcallander.o
LEXEC_OBJECTS := ${COMMON_OBJECTS} $(COMMON_CALLANDER_OBJECTS) $(PATCH_OBJECTS) lexec.o remote_exec.o tls.o attempt.o stack.o

ifeq ($(TARGETOS),linux)
CALLANDER_OPT := -Os -ftree-vectorize \
	-fauto-inc-dec -fbranch-count-reg -fcombine-stack-adjustments -fcompare-elim -fcprop-registers -fdce -fdefer-pop -fdse -fforward-propagate -fguess-branch-probability -fif-conversion -fif-conversion2 -finline-functions-called-once -fipa-profile -fipa-pure-const -fipa-reference -fipa-reference-addressable -fmerge-constants -fmove-loop-invariants -freorder-blocks -fshrink-wrap -fshrink-wrap-separate -fsplit-wide-types -fssa-backprop -fssa-phiopt -ftree-bit-ccp -ftree-ccp -ftree-ch -ftree-coalesce-vars -ftree-copy-prop -ftree-dce -ftree-dominator-opts -ftree-dse -ftree-forwprop -ftree-fre -ftree-phiprop -ftree-pta -ftree-scev-cprop -ftree-sink -ftree-slsr -ftree-sra -ftree-ter -funit-at-a-time \
	-falign-functions -falign-jumps -falign-labels -falign-loops -fcaller-saves -fcode-hoisting -fcrossjumping -fcse-follow-jumps -fcse-skip-blocks -fdelete-null-pointer-checks -fdevirtualize -fdevirtualize-speculatively -fexpensive-optimizations -fgcse -fgcse-lm -fhoist-adjacent-loads -finline-small-functions -findirect-inlining -fipa-bit-cp -fipa-cp -fipa-icf -fipa-ra -fipa-sra -fipa-vrp -fisolate-erroneous-paths-dereference -flra-remat -foptimize-sibling-calls -foptimize-strlen -fpartial-inlining -fpeephole2 -freorder-blocks-algorithm=stc -freorder-blocks-and-partition -freorder-functions -frerun-cse-after-loop -fschedule-insns -fschedule-insns2 -fsched-interblock -fsched-spec -fstore-merging -fstrict-aliasing -fthread-jumps -ftree-builtin-call-dce -ftree-pre -ftree-switch-conversion -ftree-tail-merge -ftree-vrp
else
CALLANDER_OPT := -O2
endif

objdir = .objs-$(TARGETOS)-$(TARGETMACHINE)

.PHONY: all test test-debug test-trace clean install

all: axon tests/sample tests/sample_fs tests/sample_fs_pie tests/sample_write tests/sample_dyn tests/sigsys_receive tests/fault tests/segfault target target2 target3 texec thandler callander lookup libcallbox.so libcallander.so

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
	rm -f axon texec thandler target target2 target3 callander libcallander.so libcallbox.so lookup *.debug *.o *.gcno *.gcov *.gcda tests/sample tests/sample_fs tests/sample_fs_pie tests/sample_write tests/sample_dyn tests/sigsys_receive tests/fault tests/segfault
	rm -rf "$(objdir)"

$(objdir)/%.o: %.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -fstack-usage -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) -Os -o "$@" -c "$<"

$(objdir)/callander.o: callander.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) $(CALLANDER_OPT) -o "$@" -c "$<"

ifeq ($(TARGETOS),linux)
$(objdir)/target.o: callander.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) -Oz -fno-toplevel-reorder -o "$@" -c "$<"
endif

$(objdir)/malloc.o: malloc.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -fPIC -ffreestanding -std=gnu17 $(DEBUG_FLAGS) -Os -DHAVE_MORECORE=0 -DHAVE_MMAP=1 -DUSE_DL_PREFIX=1 -DNO_MALLOC_STATS=1 -DUSE_LOCKS=0 '-DMALLOC_FAILURE_ACTION=abort();' -DLACKS_TIME_H -DHAVE_MREMAP=0 '-DDLMALLOC_EXPORT=__attribute__((visibility("hidden")))' -include axon.h -Dmalloc_getpagesize=PAGE_SIZE -o "$@" -c "$<"

axon: $(foreach obj,$(OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) -Wno-lto-type-mismatch -Wl,--exclude-libs,ALL -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $(DEBUG_FLAGS) $^ -o "$@"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

install: axon libaxon.so ld.so.preload
	mkdir -p /bin
	cp -a axon /bin/
	mkdir -p /etc
	cp -a ld.so.preload /etc/

lookup: $(foreach obj,$(LOOKUP_OBJECTS),$(objdir)/$(obj))
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
texec: $(foreach obj,$(TEXEC_OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

# payload for executing binaries remotely
thandler: $(foreach obj,$(THANDLER_OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

callander_$(TARGETMACHINE): $(foreach obj,$(CALLANDER_OBJECTS),$(objdir)/$(obj))
ifeq ($(STANDALONE),1)
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
else
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

callander: callander_$(NATIVEMACHINE)
	ln callander_$(NATIVEMACHINE) "$@" || cp -a callander_$(NATIVEMACHINE) "$@"

libcallander.so: $(foreach obj,$(LIBCALLANDER_OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"

libcallbox.so: $(foreach obj,$(LIBCALLBOX_OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"

callander_test: $(foreach obj,$(LIBCALLANDER_OBJECTS) callander_test_main.o,$(objdir)/$(obj))
ifeq ($(STANDALONE),1)
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
else
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

lexec: $(foreach obj,$(LEXEC_OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -fPIE $^ -o "$@"
# 	codesign -s gdb_codesign -o runtime --entitlements entitlements.xml "$@"

systranslate: systranslate.c defaultlibs.c syscall_defs_x86_64.h Makefile
	$(CC) $(LDFLAGS) $(DEBUG_FLAGS) -o "$@" "$<" defaultlibs.c
