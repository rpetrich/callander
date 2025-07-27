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
callander: permitted syscalls: getcwd(non-NULL, any) @ libc.so.6+0xe12ec(getcwd+108)
fcntl(any, F_SETFD, FD_CLOEXEC) @ libc.so.6+0xe3a10(__fcntl64_nocancel*+80)
fcntl(any, F_GETFL, any) @ libc.so.6+0xe3a10(__fcntl64_nocancel*+80)
ioctl(any, TCGETS, any) @ libc.so.6+0xe4414(tcgetattr+52)
openat(AT_FDCWD, any, O_RDONLY|O_CLOEXEC, any) @ libc.so.6+0xe2040(__open+96)
openat(AT_FDCWD, any, O_RDONLY|O_CLOEXEC, any) @ libc.so.6+0xe20c8(__open+232)
openat(any, any, O_RDONLY, any) @ libc.so.6+0xe2200(openat+96)
openat(any, any, O_RDONLY, any) @ libc.so.6+0xe2290(openat+240)
openat(AT_FDCWD, any, O_RDONLY|O_CLOEXEC, any) @ libc.so.6+0xe3c50(__open_nocancel+80)
openat(AT_FDCWD, non-NULL, O_RDONLY, any) @ libc.so.6+0xe3c50(__open_nocancel+80)
openat(AT_FDCWD, non-NULL, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC, any) @ libc.so.6+0xe3c50(__open_nocancel+80)
openat(AT_FDCWD, "/sys/kernel/mm/hugepages", O_RDONLY|O_DIRECTORY, any) @ libc.so.6+0xe3c50(__open_nocancel+80)
close(any) @ libc.so.6+0xddc84(close+36)
close(any) @ libc.so.6+0xddcb4(close+84)
close(any) @ libc.so.6+0xe3890(__close_nocancel+16)
getdents64(any, any, any) @ libc.so.6+0xbd69c(getdents64+28)
lseek(any, any, any) @ libc.so.6+0xe1df4(lseek+20)
read(any, any, any) @ libc.so.6+0xe2b84(__read+36)
read(any, any, any) @ libc.so.6+0xe2bc8(__read+104)
read(any, any, any) @ libc.so.6+0xe3e30(__read_nocancel+16)
write(any, any, any) @ libc.so.6+0xe37c4(write+36)
write(any, any, any) @ libc.so.6+0xe3808(write+104)
write(any, any, 0-LONG_MAX) @ libc.so.6+0xe3f70(__write_nocancel+16)
writev(any, any, any) @ ld-linux-aarch64.so.1+0xb154(_dl_debug_vdprintf*+372)
writev(STDERR_FILENO, any, any) @ libc.so.6+0x79b2c(__libc_message_impl*+332)
pread64(STDIN_FILENO-0xfffffffffffffffe, any, 511, any) @ libc.so.6+0xe3dd0(__pread64_nocancel+16)
newfstatat(any, any, any, AT_SYMLINK_NOFOLLOW) @ libc.so.6+0xdead4(fstatat64+20)
fstat(any, any) @ libc.so.6+0xdea70(fstat+16)
exit(0) @ libc.so.6+0x222bc(__libc_start_call_main*+156)
exit_group(any) @ ld-linux-aarch64.so.1+0x1be9c(_exit*+28)
exit_group(any) @ libc.so.6+0xbe1e0(_Exit+32)
futex(any, any u32, 1, 0, any, any)
futex(any, any u32, INT_MAX, 0, any, any)
futex(any, any, 0x2-0xffffffff, 0, 0, -1 as u32)
futex(any, FUTEX_WAIT|FUTEX_PRIVATE_FLAG, any u32, 0, any, any)
futex(any, FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME, 0, 0, 0, -1 as u32)
futex(any, FUTEX_WAIT_BITSET|FUTEX_PRIVATE_FLAG|FUTEX_CLOCK_REALTIME, 0, 0, 0, -1 as u32)
futex(ld-linux-aarch64.so.1+0x40a88(_rtld_global+2696), FUTEX_WAIT, any u32, 0, any, any)
futex(ld-linux-aarch64.so.1+0x40a88(_rtld_global+2696), FUTEX_LOCK_PI, 0, 0, 128, 6)
futex(ld-linux-aarch64.so.1+0x40a88(_rtld_global+2696), FUTEX_UNLOCK_PI, 0, 0, any, any)
futex(ld-linux-aarch64.so.1+0x40a88(_rtld_global+2696), FUTEX_LOCK_PI|FUTEX_PRIVATE_FLAG, 0, 0, 0, 134)
futex(ld-linux-aarch64.so.1+0x40a88(_rtld_global+2696), FUTEX_UNLOCK_PI|FUTEX_PRIVATE_FLAG, 0, 0, any, ld-linux-aarch64.so.1+0x40a98(_rtld_global+2712))
clock_gettime(CLOCK_MONOTONIC, any) @ libc.so.6+0xbca34(__clock_gettime+52)
clock_gettime(any u32, any) @ [vdso]+0x37c(__kernel_clock_gettime+188)
clock_getres(any u32, any) @ [vdso]+0x76c(__kernel_clock_getres+100)
clock_nanosleep(CLOCK_REALTIME, 0, any, any) @ libc.so.6+0xbcb5c(clock_nanosleep+60)
clock_nanosleep(CLOCK_REALTIME, 0, any, any) @ libc.so.6+0xbcba0(clock_nanosleep+128)
sched_setscheduler(any u32, any u32, any) @ libc.so.6+0xd7488(sched_setscheduler+8)
sched_getscheduler(any u32) @ libc.so.6+0xd72c8(__sched_getscheduler+8)
sched_getparam(any u32, any) @ libc.so.6+0xd7288(sched_getparam+8)
sched_getaffinity(0, 0x1000, any) @ libc.so.6+0xe749c(__get_nprocs_sched*+56)
sched_get_priority_max(1) @ libc.so.6+0xd7308(__sched_get_priority_max+8)
sched_get_priority_min(1) @ libc.so.6+0xd7348(sched_get_priority_min+8)
restart_syscall()
tgkill(any, any, SIGABRT) @ libc.so.6+0x86864(__pthread_kill_implementation*+260)
tgkill(any, any, SIGFPE) @ libc.so.6+0x86864(__pthread_kill_implementation*+260)
tgkill(any, any, SIGABRT) @ libc.so.6+0x86894(__pthread_kill_implementation*+308)
tgkill(any, any, SIGFPE) @ libc.so.6+0x86894(__pthread_kill_implementation*+308)
rt_sigaction(SIGABRT, any, 0, sizeof(kernel_sigset_t)) @ libc.so.6+0x369b0(__libc_sigaction+144)
rt_sigaction(SIGABRT, 0, 0, sizeof(kernel_sigset_t)) @ libc.so.6+0x36a50(__libc_sigaction+304)
rt_sigprocmask(SIG_UNBLOCK, any, 0, sizeof(kernel_sigset_t)) @ libc.so.6+0x21a30(abort+164)
rt_sigprocmask(SIG_BLOCK, libc.so.6+0x169da0(sigall_set*), any, sizeof(kernel_sigset_t)) @ libc.so.6+0x867c4(__pthread_kill_implementation*+100)
rt_sigprocmask(SIG_SETMASK, any, 0, sizeof(kernel_sigset_t)) @ libc.so.6+0x86810(__pthread_kill_implementation*+176)
rt_sigprocmask(SIG_SETMASK, any, 0, sizeof(kernel_sigset_t)) @ libc.so.6+0x8c5e8(pthread_sigmask+72)
prctl(PR_SET_VMA, 0, NULL-0xfffffffffffffffe, any, " glibc: fatal") @ libc.so.6+0xee684(__set_vma_name*+164)
prctl(PR_SET_VMA, 0, NULL-0xfffffffffffffffe, any, " glibc: malloc") @ libc.so.6+0xee684(__set_vma_name*+164)
prctl(PR_SET_VMA, 0, any, any, " glibc: malloc arena") @ libc.so.6+0xee684(__set_vma_name*+164)
gettimeofday(non-NULL, any) @ [vdso]+0x658(__kernel_gettimeofday+256)
getpid() @ ld-linux-aarch64.so.1+0x1bf08(__GI___getpid*+8)
getpid() @ libc.so.6+0xc41c8(getpid+8)
gettid() @ libc.so.6+0x86878(__pthread_kill_implementation*+280)
brk(any) @ libc.so.6+0xe4e90(brk+16)
munmap(any, any) @ libc.so.6+0xe9a88(munmap+8)
mremap(any, any, any, MREMAP_MAYMOVE, any) @ libc.so.6+0xee124(mremap+68)
mmap(0, any, any, any, any, 0) @ libc.so.6+0xe9040(mmap+32)
mmap(any, any, PROT_NONE, any, -1, 0) @ libc.so.6+0xe9040(mmap+32)
mprotect(any, any, any u32) @ libc.so.6+0xe9908(mprotect+8)
madvise(any, any, MADV_DONTNEED) @ libc.so.6+0xe8d88(madvise+8)
madvise(any, any, MADV_HUGEPAGE) @ libc.so.6+0xe8d88(madvise+8)
getrandom(libc.so.6+0x1b6748(tcache_key*), 8, GRND_NONBLOCK) @ libc.so.6+0x92510(ptmalloc_init.part.0*+72)
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
    Launch(Launch<br>Callander) --> ResolveProgram(Resolve Program Path) --> LoadProgram(Map Program into Memory) --> LoadLibraries
    subgraph AnalyzeProgram [Analyze Program]
        DisassembleInstructions -.-> |Discover Function<br>Pointer or Call| AnalyzeFunction
        LoadLibraries(Load Dependent Libraries) --> AnalyzeDataSections
        LoadLibraries -.->|Parse DT_NEEDED| LoadLibraries
        AnalyzeDataSections(Scan Data Sections) -->|Discover<br>Function Pointer| AnalyzeFunction
        LoadLibraries -->|Analyze Initializers| AnalyzeFunction
        AnalyzeFunction(Analyze Function) --> DisassembleInstructions
        DisassembleInstructions(Disassemble & Simulate<br>Instructions) -->|Discover<br>syscall instruction| ExtractArgs(Extract<br>Syscall Arguments) --> RecordSyscall(Record Syscall)
    end
    %%subgraph PrepareSeccomp [Prepare Seccomp]
        CoalesceSyscalls(Coalesce<br>Syscall List) --> GenerateSeccompProgram(Generate<br>Seccomp Program) --> OptimizeSeccompProgram(Peephole Optimize<br>and Split<br>Seccomp Program) --> InjectSeccompProgram(Inject<br>Seccomp Programs)
    %%end
    LoadProgram --> ForkChild
    subgraph ChildProcess [Child Process]
        ForkChild(Fork Child<br>Process) --> Ptrace(Ptrace<br>Child Process) --> ExecAndPause(Exec Target Program<br>and Pause in<br>Child Process) --> SetBreakpoint(Set Breakpoint<br>on Main Function) --> ResumeChild(Resume and<br>Wait for Break) --> InjectSeccompProgram
    end
    LoadProgram -->|Locate entrypoint| AnalyzeFunction
    InjectSeccompProgram --> ResumeProgram(Resume the now<br>Sandboxed<br>Child Process)
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
