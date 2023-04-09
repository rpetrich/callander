# Callander

## Overview

Callander is a sandboxing tool that generates right-sized system call policies
and applies them to Linux programs via seccomp. It can help you isolate the
effects of running software that might have security issues, such as memory
corruption vulnerabilities.

Callander is different from other system call sandboxing tools in that it
doesn't require any policy to be specified. Instead it analyzes any program it
is asked to run to discover the exact calls, arguments, and call sites
that the program could make. Callander uses this information to construct a
precise policy limiting the program to only the operations the program would
perform under normal circumstances. These policies can be both more precise and
more accurate than profiles assembled by hand or by observing program behavior.
Additionally, Callander waits for the process to initialize before applying a
sandboxing policy, and thus can use a more restrictive policy that blocks calls
that only occur during startup.

Running a program inside a Callander sandbox will:
1. Limit the process to performing only the system calls that Callander
  discovered it uses (use `--show-permitted` to see the allowed system calls
  permitted)
2. Load any optional libraries the program might load immediately at startup
3. Block the process from loading additional libraries after startup
4. Block the process from mapping additional executable pages after startup,
  unless this is a program that normally maps new executable pages (such as
  software that employs JIT compilation)
5. Prevent the process from remapping any of its shared libraries
6. Force all symbols to be bound at startup and its relocation tables to be
  mapped read-only
7. Block the process from executing new programs. If Callander discovers the
  program may try to execute new programs, it will error and note that you have
  the option to block executing new programs.

## Installation

Download and install an appropriate package for your distribution, or download
and untar the .tar file.

## Usage

Prefix any command you wish to run sandboxed with `callander`. Callander will
analyze, apply the sandbox, and run the program.

## Additional Options

`--block-exec` blocks calls to execute new programs

`--block-syscall NAME` blocks specific system calls. This can be used to block
operations that Callander has discovered that your program could perform, but
your specific usage of the program does not.

`--block-function NAME` blocks a specific function by its symbol name. This can
be used to disable parts of a program that you know your specific usage will not
perform. Callander will use this during analysis to further limit which system
calls are permitted.

`--main-function NAME` waits for a specific function to execute before analyzing
the remaining program. Callander will use this during analysis to further limit
which system calls are permitted.

`--show-permitted` has Callander print the system calls it permits the program
to perform before starting the program.
