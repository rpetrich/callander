# axon

Yahaha! You found me! Axon is my system for building Linux binaries that operate
without a libc, can be statically linked with self-relocation, and can be
embedded in other processes surreptitiously. It also includes mechanisms to
interact with the ELF file format, detour/patch functions, switch stacks, and
pretty-print BPF instructions. With it I've experimented on an intrusive tracer,
a library sandboxer, a proxying virtualization layer, a minimal DNS client, and
Callander. If it's of use to you, let me know. Beware, it is not well documented.
