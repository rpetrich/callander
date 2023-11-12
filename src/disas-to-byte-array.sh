#!/bin/bash
if [ -z "$1" ]; then
	echo "expected a binary to disassemble as argument" >&2
	exit 1
fi

IFS=$'\n'
for line in $(objdump -M intel --disassemble "$1" | grep -E -e ' [[:xdigit:]]*:' | cut -f 2-); do
	IFS=$' '
	for field in ${line%%$'\t'*}; do
		printf "0x%s, " $field
	done
	IFS=$'\n'
	printf "// %s\n" $(echo ${line##*$'\t'} | tr -s " ")
done
