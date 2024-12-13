#!/bin/bash
set -e

shopt -s extglob

# find architecture
arch="${arch:-$(uname -m)}"
if [ "$arch" = arm64 ]; then
	arch=aarch64
fi

if [ -z "$image" ]; then
	for file in Dockerfile.*; do
		image=${file#Dockerfile.} "$0" "$@"
	done
else
	docker build --platform=linux/$arch --progress=plain --tag "callander-test-$image-$arch:latest" --file "Dockerfile.$image" . > /dev/null
	exec docker run --platform=linux/$arch -it --mount type=bind,source=$(pwd),target=$(pwd) --env image=$image --env arch=$arch --workdir $(pwd) --security-opt seccomp=unconfined callander-test-$image-$arch "$@"
fi
