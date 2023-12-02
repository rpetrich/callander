#!/bin/bash
set -e

shopt -s extglob

# find architecture
arch=$(uname -m)
if [ "$arch" = arm64 ]; then
	arch=aarch64
fi

if [ -z "$1" ]; then
	echo "usage: $0 test_callander.sh" >&2
	exit 1
fi

build_and_test () {
	docker build --quiet --tag "callander-test-$2-$arch:latest" --file "Dockerfile.$2" . > /dev/null
	docker run -it --mount type=bind,source=$(pwd),target=$(pwd) --env image=$2 --workdir $(pwd) --security-opt seccomp=unconfined callander-test-$2-$arch $(pwd)/$1
}

if [ -z "$2" ]; then
	for file in Dockerfile.*; do
		build_and_test "$1" ${file#Dockerfile.}
	done
else
	build_and_test "$1" "$2"
fi

# docker run -it --mount type=bind,source=$(pwd),target=$(pwd) --workdir $(pwd) --security-opt seccomp=unconfined callander-test-$1
