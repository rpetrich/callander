#!/bin/bash
normal_file=$(mktemp)
axon_file=$(mktemp)
("$@" 2>&1; echo status: $?) > "$normal_file"
(AXON_TELE=0xFFFFFFFF ./axon "$@" 2>&1; echo status: $?) > "$axon_file"
if ! diff "$normal_file" <(grep -v -e '^Traced ' -e '^axon: ' "$axon_file") > /dev/null; then
	echo "test \"$@\" failed:" >&2
	echo ---
	echo normal output: >&2
	cat "$normal_file" >&2
	echo ---
	echo axon output: >&2
	grep -v -e '^Traced ' -e '^axon: ' < "$axon_file" >&2
	echo ---
	rm "$normal_file" "$axon_file"
	exit 1
fi
rm "$normal_file" "$axon_file"
