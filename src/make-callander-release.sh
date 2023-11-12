#!/bin/bash
set -e
if [ -z "$1" ]; then
	echo usage: $0 0.1
	exit 1
fi
make -j4 callander
if [ "callander $1" != "$(./callander --version)" ]; then
	echo callander binary does not report the verison you\'re releasing >&2
	exit 1
fi
git tag callander-$1
tar cfz callander-$1.tgz ./callander
