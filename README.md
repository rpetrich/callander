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

Information on how callander works was presented at All Day DevOps 2023. Slides
for this presentation are available [here](https://docs.google.com/presentation/d/1YHSBabFotD6UylVz8r4-DaJa5ZxxNUwmu-jf8bvyNgA/edit#slide=id.p).

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
callander: permitted syscalls: read(any u32, any, any) @ libc.so.6+0x10dfd0(read+16)
read(any u32, any, any) @ libc.so.6+0x10e00a(read+74)
read(any u32, any, any) @ libc.so.6+0x113606(__read_nocancel+6)
write(any u32, any, any) @ libc.so.6+0x10e075(write+21)
write(any u32, any, any) @ libc.so.6+0x10e0ad(write+77)
write(any u32, any, any) @ libc.so.6+0x113679(__write_nocancel+9)
close(any u32) @ libc.so.6+0x10e815(__close+21)
close(any u32) @ libc.so.6+0x10e839(__close+57)
close(any u32) @ libc.so.6+0x113349(__close_nocancel+9)
fstat(any u32, any) @ libc.so.6+0x10d517(__fxstat+23)
lstat(libc.so.6+0x1b420d(slashdot.10308*+3), any) @ libc.so.6+0x10d578(__lxstat64+24)
lstat(libc.so.6+0x1b5e39(dot.2585*), any) @ libc.so.6+0x10d578(__lxstat64+24)
lseek(any u32, any, any) @ libc.so.6+0x10e109(lseek64+9)
mmap(0, any, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1 as u32, 0) @ ld-linux-x86-64.so.2+0x1f184(mmap64*+36)
mmap(0, any, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT, -1 as u32, 0) @ ld-linux-x86-64.so.2+0x1f1ce(mmap64*+110)
mmap(0, any, PROT_READ, MAP_SHARED-MAP_PRIVATE, any u32, 0) @ libc.so.6+0x1188e4(mmap+36)
mmap(0, any, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1 as u32, 0) @ libc.so.6+0x1188e4(mmap+36)
mmap(0, 0x8000000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1 as u32, 0) @ libc.so.6+0x1188e4(mmap+36)
mmap(NULL-0xfffffffffffffffe, any, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1 as u32, 0) @ libc.so.6+0x1188e4(mmap+36)
mmap(any, 0x4000000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1 as u32, 0) @ libc.so.6+0x1188e4(mmap+36)
mmap(0, any, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS|MAP_32BIT, -1 as u32, 0) @ libc.so.6+0x118935(mmap+117)
mmap(0, any, PROT_READ, MAP_SHARED-MAP_PRIVATE|MAP_32BIT, any u32, 0) @ libc.so.6+0x118935(mmap+117)
mmap(0, any, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT, -1 as u32, 0) @ libc.so.6+0x118935(mmap+117)
mmap(0, 0x4000000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT|MAP_NORESERVE, -1 as u32, 0) @ libc.so.6+0x118935(mmap+117)
mmap(0, 0x8000000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT|MAP_NORESERVE, -1 as u32, 0) @ libc.so.6+0x118935(mmap+117)
mprotect(any, any, PROT_READ|PROT_WRITE) @ libc.so.6+0x1189a9(__mprotect+9)
munmap(any, any) @ libc.so.6+0x118979(munmap+9)
brk(NULL-0xfffffffffffffffe) @ libc.so.6+0x114289(brk+9)
rt_sigaction(SIGABRT, any, 0, 8) @ libc.so.6+0x43164(__libc_sigaction*+196)
rt_sigprocmask(SIG_BLOCK, any, any, 8) @ libc.so.6+0x42fc8(raise+136)
rt_sigprocmask(SIG_SETMASK, any, 0, 8) @ libc.so.6+0x43009(raise+201)
rt_sigprocmask(SIG_UNBLOCK, any, 0, 8) @ libc.so.6+0x43309(sigprocmask+73)
rt_sigreturn(any) @ libc.so.6+0x43097
ioctl(any u32, TCGETS, any) @ libc.so.6+0x113a18(tcgetattr+40)
writev(any u32, any, any) @ ld-linux-x86-64.so.2+0x12387(_dl_debug_vdprintf*+247)
writev(STDERR_FILENO, NULL-0xfffffffffffffff0, 1) @ libc.so.6+0x8cf58(__libc_message.constprop.0*+232)
writev(STDERR_FILENO, NULL-0xfffffffffffffff0, any) @ libc.so.6+0x8d1d3(__libc_message*+515)
sched_yield() @ libc.so.6+0x102719(sched_yield+9)
mremap(any, any, any, MREMAP_MAYMOVE, any) @ libc.so.6+0x11fcac(mremap+12)
madvise(NULL-0xfffffffffffffffe, any, MADV_DONTNEED) @ libc.so.6+0x118a79(__madvise+9)
getpid() @ libc.so.6+0x42fd1(raise+145)
getpid() @ libc.so.6+0x160c8c(__pthread_unwind*+28)
exit(0) @ libc.so.6+0x240e4(__libc_start_main+340)
kill(getpid(), SIGKILL) @ libc.so.6+0x160c9a(__pthread_unwind*+42)
fcntl(any u32, F_SETFD, 1) @ libc.so.6+0x1133b3(__GI___fcntl64_nocancel*+67)
fcntl(any u32, F_GETFL, any) @ libc.so.6+0x1133b3(__GI___fcntl64_nocancel*+67)
getcwd(non-NULL, any) @ libc.so.6+0x10eaf0(getcwd+128)
gettimeofday(non-NULL, any) @ [vdso]+0x6c5(gettimeofday+69)
sysinfo(any) @ libc.so.6+0x11fdc9(sysinfo+9)
gettid() @ libc.so.6+0x42fdb(raise+155)
futex(any, FUTEX_WAIT|FUTEX_PRIVATE_FLAG, any, 0, any u32, any)
futex(any, FUTEX_WAIT|FUTEX_PRIVATE_FLAG, 2, 0, any, any)
futex(any, FUTEX_WAKE|FUTEX_PRIVATE_FLAG, 1, 0, any, any)
getdents64(any u32, any, any) @ libc.so.6+0xde2b9(getdents64+25)
restart_syscall()
clock_gettime(CLOCK_REALTIME, any) @ libc.so.6+0xdd0f2(clock_gettime+98)
clock_gettime(CLOCK_REALTIME_COARSE, any) @ libc.so.6+0xdd0f2(clock_gettime+98)
clock_gettime(any u32, any) @ [vdso]+0x89f(__vdso_clock_gettime+95)
clock_getres(any u32, any) @ [vdso]+0x66b
clock_nanosleep(CLOCK_REALTIME, 0, any, any) @ libc.so.6+0xdd1b2(clock_nanosleep+82)
clock_nanosleep(CLOCK_REALTIME, 0, any, any) @ libc.so.6+0xdd23d(clock_nanosleep+221)
clock_nanosleep(CLOCK_MONOTONIC, 0, any, any) @ libc.so.6+0xdd288(clock_nanosleep+296)
clock_nanosleep(CLOCK_MONOTONIC, 0, any, any) @ libc.so.6+0xdd2f9(clock_nanosleep+409)
clock_nanosleep(CLOCK_MONOTONIC, 0, any, any) @ libc.so.6+0xdd31f(clock_nanosleep+447)
clock_nanosleep(CLOCK_MONOTONIC, 0, any, any) @ libc.so.6+0xdd372(clock_nanosleep+530)
exit_group(NULL-0x1fe) @ ld-linux-x86-64.so.2+0x1f2bc(_exit*+44)
exit_group(any u32) @ libc.so.6+0xe3144(_Exit+52)
tgkill(getpid(), any u32, SIGABRT) @ libc.so.6+0x42fe7(raise+167)
tgkill(getpid(), any u32, SIGFPE) @ libc.so.6+0x42fe7(raise+167)
openat(AT_FDCWD, NULL-0xfffffffffffffff0, any u32, any) @ libc.so.6+0x10dd39(open+89)
openat(AT_FDCWD, NULL-0xfffffffffffffff0, any u32, any) @ libc.so.6+0x10ddb2(open+210)
openat(AT_FDCWD, any, any u32, any) @ libc.so.6+0x1134fa(__open_nocancel+74)
openat(any u32, libc.so.6+0x1b5e38, O_RDONLY|O_CLOEXEC, any) @ libc.so.6+0x113598(__openat64_nocancel*+56)
newfstatat(any u32, any, any, AT_SYMLINK_NOFOLLOW) @ libc.so.6+0x10d9bd(__fxstatat+29)
prlimit64(0, RLIMIT_NOFILE, 0, any) @ libc.so.6+0x113d72(getrlimit+18)
hi
```

## Limitations

Programs that launch other programs are not supported by callander, due to the
limitations of seccomp. If asked to run a program that does `exec` other
programs, callander will emit an error that can be overridden with the
`--block-exec` option.

Only x86-64 Linux binaries are supported. A version for aarch64 is in
development, but not yet available.

Additionally, callander is beta software and requires more real-world testing.
If you have a program that it doesn't analyze properly or rejects, please open
an issue.

## Building

Callander can be built by running make:

```bash
git clone git@github.com:rpetrich/callander.git
cd callander/src
make -j4
```

For best results, use gcc 9.4.0 on ubuntu 20.04 to produce completely static
binaries that run on any recent Linux kernel.
