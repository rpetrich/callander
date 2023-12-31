#!/bin/bash
ROSETTA_DEBUGSERVER_PORT=1234 "$@" &
INFERIOR_PID=$! exec gdb -ex "set architecture i386:x86-64" -ex "file $1" -ex "target remote localhost:1234"
