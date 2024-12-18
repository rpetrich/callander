# ![callander](callander-logo.png)

Callander is a simple system sandboxing tool for Linux. It uses program analysis
to generate and apply right-sized seccomp sandboxes to programs. It can help you
isolate the effects of software that might have security issues, such as memory
corruption vulnerabilities. For many programs, using it is as simple as
prefixing your command with `callander`.

Callander is different from other system call sandboxing tools in that it
doesn't require any policy to be specified. Instead it analyzes any program it
is asked to run to discover the exact calls, arguments, and call sites
that the program could make. Callander uses this information to construct a
precise policy limiting the program to only the operations the program could
normally perform. These policies can be both more precise and more accurate than
profiles assembled by hand or by observing program behavior. Even the most
obscure error paths are analyzed and accounted for, unlike with
observation-derived system call lists. Additionally, Callander waits for the
process to initialize before applying a sandboxing policy, and thus can use
a more restrictive policy that blocks calls that only occur during startup. This
means many programs can run without the ability to forge executable memory
mappings.

Information on how callander works was presented at All Day DevOps 2023.
[Slides](https://docs.google.com/presentation/d/1YHSBabFotD6UylVz8r4-DaJa5ZxxNUwmu-jf8bvyNgA/edit#slide=id.p)
and [a recording](https://play.vidyard.com/QnNz346tpULkHSwNSDy4oJ) of this talk
are available.

![demo of callander protecting nginx from attack](callander-demo.gif)

## Installation

1. Download a .tgz from https://github.com/rpetrich/callander/releases/latest
2. Extract with `tar xfz callander-*.tgz` or a graphical decompression utility
3. Run a command prefixed with the path to `callander`

## Usage

Prefix any command you wish to run sandboxed with `callander`. Callander will
analyze, apply the sandbox, and run the program.

Add the `--show-permitted` option to see which system calls callander has
discovered your command uses:

```
$ callander --show-permitted echo hi
callander: permitted syscalls: getcwd(non-NULL, any) @ libc.so.6+0xd889c(getcwd+124)
callander: permitted syscalls: read(any u32, any, any) @ libc.so.6+0x1147e0(__read+16)
read(any u32, any, any) @ libc.so.6+0x11481a(__read+74)
read(any u32, any, any) @ libc.so.6+0x119b26(__read_nocancel+6)
write(any u32, any, any) @ libc.so.6+0x114885(__write+21)
write(any u32, any, any) @ libc.so.6+0x1148bd(__write+77)
write(any u32, any, any) @ libc.so.6+0x119b99(__write_nocancel+9)
close(any u32) @ libc.so.6+0x114f65(__close+21)
close(any u32) @ libc.so.6+0x114f89(__close+57)
close(any u32) @ libc.so.6+0x119869(__close_nocancel+9)
lseek(any u32, any, any) @ libc.so.6+0x114919(__lseek+9)
mmap(0, any, PROT_READ|PROT_WRITE, any u32, -1 as u32, 0) @ libc.so.6+0x11ea25(mmap+21)
mmap(any, any, PROT_NONE-PROT_READ, any u32, any u32, 0) @ libc.so.6+0x11ea25(mmap+21)
mprotect(any, any, PROT_READ|PROT_WRITE) @ libc.so.6+0x11eaa9(__mprotect+9)
munmap(any, any) @ libc.so.6+0x11ea79(__munmap+9)
brk(any) @ libc.so.6+0x11a829(brk+9)
rt_sigaction(SIGABRT, any, 0, 8) @ libc.so.6+0x425f1(__libc_sigaction+193)
rt_sigprocmask(SIG_BLOCK, libc.so.6+0x1d2a60(sigall_set*), any, 8) @ libc.so.6+0x96933(pthread_kill+99)
rt_sigprocmask(SIG_SETMASK, any, 0, 8) @ libc.so.6+0x96980(pthread_kill+176)
rt_sigprocmask(SIG_UNBLOCK-SIG_SETMASK, any, 0, 8) @ libc.so.6+0x9bc19(pthread_sigmask+73)
rt_sigreturn(any) @ libc.so.6+0x42527
ioctl(any u32, TCGETS, any) @ libc.so.6+0x119f48(tcgetattr+40)
pread64(STDIN_FILENO-0xfffffffe, any, 511, 0) @ libc.so.6+0x119b5c(__pread64_nocancel+12)
writev(any u32, any, any) @ ld-linux-x86-64.so.2+0xf5c2(_dl_debug_vdprintf*+258)
writev(STDERR_FILENO, any, 1) @ libc.so.6+0x89368(__libc_message.constprop.0*+232)
writev(STDERR_FILENO, any, any) @ libc.so.6+0x895db(__libc_message*+507)
sched_yield() @ libc.so.6+0x108c99(sched_yield+9)
mremap(any, any, any, MREMAP_MAYMOVE, any) @ libc.so.6+0x12696d(mremap+45)
madvise(any, any, MADV_DONTNEED) @ libc.so.6+0x11eb79(madvise+9)
madvise(any, any, MADV_HUGEPAGE) @ libc.so.6+0x11eb79(madvise+9)
getpid() @ ld-linux-x86-64.so.2+0x26ee9(__GI___getpid*+9)
getpid() @ libc.so.6+0xec049(__getpid+9)
exit(0) @ libc.so.6+0x29db4(__libc_start_call_main*+164)
fcntl(any u32, F_SETFD, 1) @ libc.so.6+0x1198d3(__fcntl64_nocancel*+67)
fcntl(any u32, F_GETFL, any) @ libc.so.6+0x1198d3(__fcntl64_nocancel*+67)
getcwd(non-NULL, any) @ libc.so.6+0x115263(getcwd+147)
sysinfo(any) @ libc.so.6+0x126de9(sysinfo+9)
sched_getparam(any u32, any) @ libc.so.6+0x108c09(sched_getparam+9)
sched_setscheduler(any u32, any u32, any) @ libc.so.6+0x108c39(__sched_setscheduler+9)
sched_getscheduler(any u32) @ libc.so.6+0x108c69(sched_getscheduler+9)
sched_get_priority_max(1) @ libc.so.6+0x108cc9(sched_get_priority_max+9)
sched_get_priority_min(1) @ libc.so.6+0x108cf9(__sched_get_priority_min+9)
gettid() @ libc.so.6+0x969e5(pthread_kill+277)
futex(any, any u8, 1, 0, any u32, any)
futex(any, any u8, 1, 0, any, any u32)
futex(any, any u8, INT_MAX, 0, any, any)
futex(any, any u32, any u32, 0, 0, -1 as u32)
futex(any, FUTEX_WAIT|FUTEX_PRIVATE_FLAG, 2, 0, any, any)
futex(any, FUTEX_WAKE|FUTEX_PRIVATE_FLAG, 1, 0, any, any)
futex(ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), FUTEX_WAIT, NULL-0xfff80002, 0, NULL-0xfff80000, NULL-0xfff80001)
futex(ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), FUTEX_WAIT, 0x1-0xffffffff, 0, 0, ld-linux-x86-64.so.2+0x3aa68(_rtld_global+2600))
futex(ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), FUTEX_WAIT, 0x1-0xffffffff, 0, 0x40000000, ld-linux-x86-64.so.2+0x3aa68(_rtld_global+2600))
futex(ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), FUTEX_WAIT, 2, 0, 128, any)
futex(ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), FUTEX_WAKE, 1, 0, any, any)
futex(ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), FUTEX_LOCK_PI, 0, 0, 0, any)
futex(ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), FUTEX_UNLOCK_PI, 0, 0, any, any)
futex(ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), FUTEX_WAIT|FUTEX_PRIVATE_FLAG, NULL-0xfff80002, 0, NULL-0xfff80000, NULL-0xfff80001)
futex(ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), FUTEX_LOCK_PI|FUTEX_PRIVATE_FLAG, 0, 0, 0, any)
futex(ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), FUTEX_UNLOCK_PI|FUTEX_PRIVATE_FLAG, 0, 0, ld-linux-x86-64.so.2+0x3aa48(_rtld_global+2568), any)
futex(libc.so.6+0x21ba6c(once*), FUTEX_WAIT|FUTEX_PRIVATE_FLAG, any u32, 0, 202, 2177)
futex(libc.so.6+0x228a80(once.0*), FUTEX_WAIT|FUTEX_PRIVATE_FLAG, any u32, 0, 202, 2177)
sched_getaffinity(0, 0x1000, any) @ libc.so.6+0x121a66(__get_nprocs_sched*+54)
getdents64(any u32, any, any) @ libc.so.6+0xe6645(getdents64+21)
restart_syscall()
clock_gettime(CLOCK_REALTIME-CLOCK_MONOTONIC, any) @ libc.so.6+0xe5685(clock_gettime+53)
clock_nanosleep(CLOCK_REALTIME, 0, any, any) @ libc.so.6+0xe5788(clock_nanosleep+88)
clock_nanosleep(CLOCK_REALTIME, 0, any, any) @ libc.so.6+0xe57f6(clock_nanosleep+198)
clock_nanosleep(CLOCK_MONOTONIC, 0, any, any) @ libc.so.6+0xe584d(clock_nanosleep+285)
clock_nanosleep(CLOCK_MONOTONIC, 0, any, any) @ libc.so.6+0xe58e1(clock_nanosleep+433)
exit_group(NULL-0x1fe) @ ld-linux-x86-64.so.2+0x26eaf(_exit*+31)
exit_group(2048) @ ld-linux-x86-64.so.2+0x26eaf(_exit*+31)
exit_group(any u32) @ libc.so.6+0xeac2f(_exit+47)
tgkill(any u32, any u32, SIGABRT) @ libc.so.6+0x969c9(pthread_kill+249)
tgkill(any u32, any u32, SIGFPE) @ libc.so.6+0x969c9(pthread_kill+249)
tgkill(any u32, any u32, SIGABRT) @ libc.so.6+0x969fa(pthread_kill+298)
tgkill(any u32, any u32, SIGFPE) @ libc.so.6+0x969fa(pthread_kill+298)
openat(AT_FDCWD, any, O_RDONLY|O_CLOEXEC, any) @ libc.so.6+0x114539(__open+89)
openat(AT_FDCWD, any, O_RDONLY|O_CLOEXEC, any) @ libc.so.6+0x1145b2(__open+210)
openat(any u32, libc.so.6+0x1da05c, O_RDONLY, any) @ libc.so.6+0x1146b4(openat+68)
openat(any u32, libc.so.6+0x1da05c, O_RDONLY, any) @ libc.so.6+0x114741(openat+209)
openat(AT_FDCWD, any, O_RDONLY|O_CLOEXEC, any) @ libc.so.6+0x119a1a(__open_nocancel+74)
openat(AT_FDCWD, non-NULL, O_RDONLY, any) @ libc.so.6+0x119a1a(__open_nocancel+74)
openat(AT_FDCWD, non-NULL, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC, any) @ libc.so.6+0x119a1a(__open_nocancel+74)
openat(AT_FDCWD, libc.so.6+0x1db5f4, O_RDONLY|O_DIRECTORY, any) @ libc.so.6+0x119a1a(__open_nocancel+74)
newfstatat(any u32, any, any, AT_SYMLINK_NOFOLLOW) @ libc.so.6+0x113d3c(fstatat64+12)
newfstatat(any u32, libc.so.6+0x1d844f, any, AT_EMPTY_PATH) @ libc.so.6+0x113d3c(fstatat64+12)
prlimit64(0, RLIMIT_NOFILE, 0, any) @ libc.so.6+0x11a2e2(getrlimit+18)
getrandom(libc.so.6+0x2214d8(tcache_key*), 8, GRND_NONBLOCK) @ libc.so.6+0x46c85(getrandom+21)
getrandom(libc.so.6+0x2214d8(tcache_key*), 8, GRND_NONBLOCK) @ libc.so.6+0x46cbd(getrandom+77)
hi
```

## Limitations

Programs that launch other programs are not supported by callander, due to the
limitations of seccomp. If asked to run a program that does `exec` other
programs, callander will emit an error that can be overridden with the
`--block-exec` option.

x86_64 and aarch64 linux binaries are available. No support for other
architectures is planned.

Additionally, callander is beta software and requires more real-world testing.
If you have a program that it doesn't analyze properly or rejects, please open
an issue.

## Architecture

Callander's high-level architecture is a hybrid of patterns found in binary
analysis tools, debuggers, and simple compilers.

```mermaid
flowchart 
    AnalyzeProgram --> CoalesceSyscalls
    Launch(Launch\nCallander) --> ResolveProgram(Resolve Program Path) --> LoadProgram(Map Program into Memory) --> LoadLibraries
    subgraph AnalyzeProgram [Analyze Program]
        DisassembleInstructions -.-> |Discover Function\nPointer or Call| AnalyzeFunction
        LoadLibraries(Load Dependent Libraries) --> AnalyzeDataSections
        LoadLibraries -.->|Parse DT_NEEDED| LoadLibraries
        AnalyzeDataSections(Scan Data Sections) -->|Discover\nFunction Pointer| AnalyzeFunction
        LoadLibraries -->|Analyze Initializers| AnalyzeFunction
        AnalyzeFunction(Analyze Function) --> DisassembleInstructions
        DisassembleInstructions(Disassemble & Simulate\nInstructions) -->|Discover\nsyscall instruction| ExtractArgs(Extract\nSyscall Arguments) --> RecordSyscall(Record Syscall)
    end
    %%subgraph PrepareSeccomp [Prepare Seccomp]
        CoalesceSyscalls(Coalesce\nSyscall List) --> GenerateSeccompProgram(Generate\nSeccomp Program) --> OptimizeSeccompProgram(Peephole Optimize\nand Split\nSeccomp Program) --> InjectSeccompProgram(Inject\nSeccomp Programs)
    %%end
    LoadProgram --> ForkChild
    subgraph ChildProcess [Child Process]
        ForkChild(Fork Child\nProcess) --> Ptrace(Ptrace\nChild Process) --> ExecAndPause(Exec Target Program\nand Pause in\nChild Process) --> SetBreakpoint(Set Breakpoint\non Main Function) --> ResumeChild(Resume and\nWait for Break) --> InjectSeccompProgram
    end
    LoadProgram -->|Locate entrypoint| AnalyzeFunction
    InjectSeccompProgram --> ResumeProgram(Resume the now\nSandboxed\nChild Process)
```

## Building

Callander can be built by running make:

```bash
git clone git@github.com:rpetrich/callander.git
cd callander/src
make -j4
```

For best results, use a modern version of gcc to produce completely static
binaries that run on any recent Linux kernel.

## Special Thanks

The logo was generously provided by my frequent collaborator, [Kelly Shortridge](https://kellyshortridge.com/). Without this and other contributions, Callander would not exist.

aarch64 disassembly uses Vector35's [arm64 disassembler](https://github.com/Vector35/binaryninja-api/tree/dev/arch/arm64).

x86 disassembly uses length disassembler by Stefan Johnson.
