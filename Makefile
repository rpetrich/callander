NATIVEMACHINE ?= $(shell uname -m)
TARGETMACHINE ?= $(shell uname -m)
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
	CFLAGS+=-mno-red-zone -mfsgsbase
	LDFLAGS+=-mfsgsbase
endif
else
	CFLAGS=-m32
	LDFLAGS=-m32
	BASE_ADDRESS=0x08040000
endif

ifneq ($(NATIVEMACHINE),$(TARGETMACHINE))
	CC = $(TARGETMACHINE)-$(TARGETOS)-gnu-gcc
	export PATH := /usr/$(TARGETMACHINE)-$(TARGETOS)-gnu/bin:$(PATH)
endif
OBJCOPY ?= objcopy
STRIP ?= strip

CFLAGS += -DPRODUCT_NAME='"callander"'

CFLAGS += -flto -fvisibility=hidden -ffunction-sections -fdata-sections
LDFLAGS += -flto -fvisibility=hidden -Wl,--gc-sections

# record stack usage to objs-*/*.su
# CFLAGS += -fstack-usage
# LDFLAGS += -fstack-usage

CFLAGS += -fno-omit-frame-pointer -fno-asynchronous-unwind-tables -Werror -Wall -Wextra -Wno-missing-braces -Wuninitialized -Wunused-parameter -Wtype-limits -Wsign-compare -Wimplicit-fallthrough -Wshadow -Wdouble-promotion -Wundef -fcf-protection=none
ifeq ($(shell $(CC) --version | grep -o 'Free Software Foundation'),Free Software Foundation)
	CFLAGS += -mgeneral-regs-only -Wold-style-declaration -Wmissing-parameter-type
ifeq ($(TARGETMACHINE),aarch64)
	CFLAGS += -Wno-psabi
	LDFLAGS += -Wno-psabi
	CFLAGS += -Wno-unused-function
endif
else
ifeq ($(CC),clang)
ifeq ($(TARGETMACHINE),aarch64)
	CFLAGS += -mgeneral-regs-only
else
	CFLAGS += -mno-sse
endif
endif
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

STANDALONE ?= 1

OBJECTS := attempt.o axon.o coverage.o darwin.o debugger.o defaultlibs.o \
			exec.o fd_table.o fork.o install.o intercept.o handler.o libraries.o \
			loader.o mapped.o patch.o patch_aarch64.o patch_x86_64.o paths.o \
			preload.o proxy.o qsort.o remote.o remote_library.o resolver.o search.o seccomp.o \
			sockets.o stack.o time.o tls.o tracer.o x86.o x86_64_length_disassembler.o
TEXEC_OBJECTS := attempt.o darwin.o defaultlibs.o exec.o fd_table.o \
		    loader.o proxy.o qsort.o remote.o search.o seccomp.o \
		    stack.o texec.o time.o tls.o x86.o \
		    callander.o callander_print.o patch_x86_64.o x86_64_length_disassembler.o
THANDLER_OBJECTS := attempt_target.o defaultlibs.o exec_target.o fd_table_target.o \
			fork_target.o handler.o intercept_target.o malloc.o paths_target.o proxy_target.o \
			remote.o remote_library_target.o sockets_target.o stack.o thandler.o tls.o tracer.o
COMMON_CALLANDER_OBJECTS := bpf_debug.o callander.o callander_print.o defaultlibs.o loader.o \
			mapped.o qsort.o search.o x86.o \
			x86_64_length_disassembler.o
LOOKUP_OBJECTS := defaultlibs.o loader.o lookup_main.o resolver.o
LIBCALLBOX_OBJECTS := libcallbox.o attempt.o $(COMMON_CALLANDER_OBJECTS) defaultlibs.o loader.o mapped.o patch.o patch_aarch64.o patch_x86_64.o proxy.o tls.o x86.o x86_64_length_disassembler.o
ifeq ($(STANDALONE),1)
	CFLAGS += -DSTANDALONE=1
	OBJECTS += malloc.o
	TEXEC_OBJECTS += malloc.o
	COMMON_CALLANDER_OBJECTS += malloc.o
	LOOKUP_OBJECTS += malloc.o
	LIBCALLBOX_OBJECTS += malloc.o
endif

CALLANDER_OBJECTS := $(COMMON_CALLANDER_OBJECTS) callander_main.o
LIBCALLANDER_OBJECTS := $(COMMON_CALLANDER_OBJECTS) libcallander.o

CALLANDER_OPT := -Os -ftree-vectorize \
	-fauto-inc-dec -fbranch-count-reg -fcombine-stack-adjustments -fcompare-elim -fcprop-registers -fdce -fdefer-pop -fdse -fforward-propagate -fguess-branch-probability -fif-conversion -fif-conversion2 -finline-functions-called-once -fipa-profile -fipa-pure-const -fipa-reference -fipa-reference-addressable -fmerge-constants -fmove-loop-invariants -freorder-blocks -fshrink-wrap -fshrink-wrap-separate -fsplit-wide-types -fssa-backprop -fssa-phiopt -ftree-bit-ccp -ftree-ccp -ftree-ch -ftree-coalesce-vars -ftree-copy-prop -ftree-dce -ftree-dominator-opts -ftree-dse -ftree-forwprop -ftree-fre -ftree-phiprop -ftree-pta -ftree-scev-cprop -ftree-sink -ftree-slsr -ftree-sra -ftree-ter -funit-at-a-time \
	-falign-functions -falign-jumps -falign-labels -falign-loops -fcaller-saves -fcode-hoisting -fcrossjumping -fcse-follow-jumps -fcse-skip-blocks -fdelete-null-pointer-checks -fdevirtualize -fdevirtualize-speculatively -fexpensive-optimizations -fgcse -fgcse-lm -fhoist-adjacent-loads -finline-small-functions -findirect-inlining -fipa-bit-cp -fipa-cp -fipa-icf -fipa-ra -fipa-sra -fipa-vrp -fisolate-erroneous-paths-dereference -flra-remat -foptimize-sibling-calls -foptimize-strlen -fpartial-inlining -fpeephole2 -freorder-blocks-algorithm=stc -freorder-blocks-and-partition -freorder-functions -frerun-cse-after-loop -fschedule-insns -fschedule-insns2 -fsched-interblock -fsched-spec -fstore-merging -fstrict-aliasing -fthread-jumps -ftree-builtin-call-dce -ftree-pre -ftree-switch-conversion -ftree-tail-merge -ftree-vrp

objdir = .objs-$(TARGETMACHINE)

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
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -fstack-usage -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 -g3 -Os -o "$@" -c "$<"

$(objdir)/callander.o: callander.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 -g3 $(CALLANDER_OPT) -o "$@" -c "$<"

$(objdir)/target.o: callander.c *.h Makefile
	mkdir -p $(dir $@) && $(CC) $(CFLAGS) -I/usr/local/include -Wno-error=frame-address -fPIC -ffreestanding -std=gnu17 -g3 -Oz -fno-toplevel-reorder -o "$@" -c "$<"

$(objdir)/malloc.o: malloc.c *.h Makefile
	$(CC) $(CFLAGS) -fPIC -ffreestanding -std=gnu17 -g3 -Os -DHAVE_MORECORE=0 -DHAVE_MMAP=1 -DUSE_DL_PREFIX=1 -DNO_MALLOC_STATS=1 -DUSE_LOCKS=0 '-DMALLOC_FAILURE_ACTION=abort();' -DLACKS_TIME_H -DHAVE_MREMAP=0 '-DDLMALLOC_EXPORT=__attribute__((visibility("hidden")))' -include axon.h -Dmalloc_getpagesize=PAGE_SIZE -o "$@" -c "$<"

axon: $(foreach obj,$(OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) -Wno-lto-type-mismatch -Wl,--exclude-libs,ALL -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g3 $^ -o "$@"
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
	$(CC) $(LDFLAGS) -g3 -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g3 $^ -o "$@"
else
	$(CC) $(LDFLAGS) -g3 -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g3 $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

tests/sample: tests/sample.c *.h Makefile
	$(CC) $(LDFLAGS) -g -static -no-pie -ffreestanding -o "$@" "$<"

tests/sample_dyn: tests/sample.c *.h Makefile
	$(CC) $(LDFLAGS) -g -o "$@" "$<"

tests/sample_fs: tests/sample_fs.c *.h Makefile
	$(CC) $(LDFLAGS) -g -static -nostdlib -no-pie -O2 -ffreestanding -Wl,-e,impulse -o "$@" "$<"

tests/sample_fs_pie: tests/sample_fs.c *.h Makefile
	$(CC) $(LDFLAGS) -g -nostdlib -pie -fPIC -O2 -ffreestanding -Wl,-e,impulse -o "$@" "$<"

tests/sample_write: tests/sample_write.c *.h Makefile
	$(CC) $(LDFLAGS) -g -nostdlib -fPIC -O2  -nostdlib -shared -nostartfiles -ffreestanding -Wl,-e,impulse -o "$@" "$<"

tests/sigsys_receive: tests/sigsys_receive.c Makefile
	$(CC) $(LDFLAGS) -g -static -no-pie -ffreestanding -o "$@" "$<"

tests/fault: tests/fault.c *.h Makefile
	$(CC) $(LDFLAGS) -g -static -no-pie -ffreestanding -o "$@" "$<"

tests/segfault: tests/segfault.c *.h Makefile
	$(CC) $(LDFLAGS) -g -static -no-pie -ffreestanding -o "$@" "$<"

# full axon target payload
target: target.c *.h Makefile
ifeq ($(TARGETOS),linux)
	$(CC) $(CFLAGS) $(LDFLAGS) -g -nostdlib -shared -nostartfiles -ffreestanding -fPIC -Os -ffreestanding -Wl,-e,release -Wl,--build-id=none -Wl,--no-dynamic-linker -fcf-protection=none -fno-asynchronous-unwind-tables  -fno-toplevel-reorder -o "$@" "$<"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"
else
	$(CC) $(LDFLAGS) -g -o "$@" "$<"
endif

# basic remote shell payload
target2: target2.c *.h Makefile
ifeq ($(TARGETOS),linux)
	$(CC) $(CFLAGS) $(LDFLAGS) -g -nostdlib -shared -nostartfiles -ffreestanding -fPIC -Os -ffreestanding -Wl,-e,release -Wl,--build-id=none -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -fcf-protection=none -fno-asynchronous-unwind-tables  -fno-toplevel-reorder -o "$@" "$<"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"
else
	$(CC) $(LDFLAGS) -g -o "$@" "$<"
endif

# intermediary payload
target3: target3.c *.h Makefile
ifeq ($(TARGETOS),linux)
	$(CC) $(CFLAGS) $(LDFLAGS) -g -nostdlib -shared -nostartfiles -ffreestanding -fPIC -Os -ffreestanding -Wl,-e,release -Wl,--build-id=none -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -fcf-protection=none -fno-asynchronous-unwind-tables  -fno-toplevel-reorder -o "$@" "$<"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"
else
	$(CC) $(LDFLAGS) -g -o "$@" "$<"
endif

# executes binaries remotely
texec: $(foreach obj,$(TEXEC_OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) -g -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g $^ -o "$@"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

# payload for executing binaries remotely
thandler: $(foreach obj,$(THANDLER_OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) -g -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g $^ -o "$@"
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

callander: $(foreach obj,$(CALLANDER_OBJECTS),$(objdir)/$(obj))
ifeq ($(STANDALONE),1)
	$(CC) $(LDFLAGS) -g -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g $^ -o "$@"
else
	$(CC) $(LDFLAGS) -g -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

libcallander.so: $(foreach obj,$(LIBCALLANDER_OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) -g -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g $^ -o "$@"

libcallbox.so: $(foreach obj,$(LIBCALLBOX_OBJECTS),$(objdir)/$(obj))
	$(CC) $(LDFLAGS) -g3 -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g $^ -o "$@"

callander_test: $(foreach obj,$(LIBCALLANDER_OBJECTS) callander_test_main.o,$(objdir)/$(obj))
ifeq ($(STANDALONE),1)
	$(CC) $(LDFLAGS) -g -Wl,--exclude-libs,ALL -Wl,--build-id=none -nostdlib -shared -nostartfiles -ffreestanding -fPIC $(CFLAGS) -Wl,-e,impulse -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,--no-dynamic-linker -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g $^ -o "$@"
else
	$(CC) $(LDFLAGS) -g -Wl,--build-id=none -fPIE $(CFLAGS) -Wl,--hash-style=both -Wl,-z,defs -Wl,-z,now -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-zcommon-page-size=0x1000 -Wl,-zmax-page-size=0x1000 -Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,nodelete -Wl,-z,nodump -Wl,-z,combreloc -g $^ -o "$@"
endif
	$(OBJCOPY) --only-keep-debug "$@" "$@.debug"
	$(STRIP) -s -R .comment -D "$@"
	$(OBJCOPY) --add-gnu-debuglink="$@.debug" "$@"

systranslate: systranslate.c defaultlibs.c syscall_defs_x86_64.h Makefile
	$(CC) $(LDFLAGS) -g -o "$@" "$<" defaultlibs.c
