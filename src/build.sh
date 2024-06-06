#!/bin/bash
set -e

shopt -s extglob

# find architecture
arch="${arch:-$(uname -m)}"
if [ "$arch" = arm64 ]; then
	arch=aarch64
fi

docker build --platform=linux/$arch --quiet --tag axon-builder:latest --file Dockerfile . > /dev/null
exec docker run --platform=linux/$arch -it --mount type=bind,source=$(pwd),target=$(pwd) --env image=axon-builder:latest --workdir $(pwd) axon-builder make "$@"
