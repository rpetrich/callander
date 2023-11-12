#!/bin/bash
# generates the constant used in fs_strerror
line="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
for i in `seq 1 133`; do
	name=$(errno $i | cut -d ' ' -f 1)
	printf '	"%s%s"\n' $name "${line:$((2 * ${#name}))}"
done
