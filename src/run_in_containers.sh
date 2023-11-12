#!/bin/bash
set -e

shopt -s extglob

if [ -z "$1" ]; then
	echo "usage: $0 test_callander.sh" >&2
	exit 1
fi

build_and_test () {
	# docker build --tag "callander-test-$2:latest" --file "Dockerfile.$2" .	
	docker run -it --mount type=bind,source=$(pwd),target=$(pwd) --env image=$2 --workdir $(pwd) --security-opt seccomp=unconfined callander-test-$2 $(pwd)/$1
}

if [ -z "$2" ]; then
	for file in Dockerfile.*; do
		build_and_test "$1" ${file#Dockerfile.}
	done
else
	build_and_test "$1" "$2"
fi

# docker run -it --mount type=bind,source=$(pwd),target=$(pwd) --workdir $(pwd) --security-opt seccomp=unconfined callander-test-$1
