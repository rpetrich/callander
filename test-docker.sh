#!/bin/bash
set -e

if [ ! -e "Dockerfile.$1" ]; then
	echo "expected \"$0 alpine\" or similar" >&2
	exit 1
fi

docker build --tag "callander-test-$1:latest" --file "Dockerfile.$1" .
docker run -it --mount type=bind,source=$(pwd),target=$(pwd) --workdir $(pwd) --security-opt seccomp=unconfined callander-test-alpine
# $(pwd)/test_callander.sh
