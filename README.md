# callander

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

## Installation

1. Download a .tgz from https://github.com/rpetrich/callander/releases/latest
2. Extract with `tar xfz callander-*.tgz` or a graphical decompression utility
3. Run `callander`

## Usage

Prefix any command you wish to run sandboxed with `callander`. Callander will
analyze, apply the sandbox, and run the program.

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
cd callander
make -j4
```

For best results, use gcc 9.4.0 on ubuntu 20.04 to produce completely static
binaries that run on any recent Linux kernel.
