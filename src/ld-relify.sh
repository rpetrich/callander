#!/bin/bash
set -e
rel_interp="$(pwd)/ld-rel.so"
existing_rel="$(patchelf --print-interpreter "$1")"
if [ "$existing_rel" = "$rel_interp" ]; then
	echo "already patched" >&1
	exit 0
fi
local_path="$(dirname "$1")"
if ! [ -e "$" ]; then
	cp "$existing_rel" "$local_path"
fi
exec patchelf --set-interpreter "$rel_interp" --add-rpath '$ORIGIN/../'"$(basename $existing_rel)" "$1"
