#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

source /etc/os-release
FIXTURE_PATH="$SCRIPT_DIR/sysfilter_fixtures_"$ID"_"$VERSION_ID

test_program () {
	local prog="$1"
	local filename="${prog##*/}"
	filename="${prog##*/}"
	if [ -g "$prog" -o -u "$prog" ]; then
		rm -f "$FIXTURE_PATH/$filename.txt"
	else
		if [ "/sbin/$filename" = "$prog" -a -e "/bin/$filename" ]; then
			# skipping since duplicate binary in /sbin
			return
		else
			LD_LIBRARY_PATH=. "$SCRIPT_DIR/sysfilter_extract" --syscalls-flat "$prog" > "$FIXTURE_PATH/$filename"_new.txt 2>&1
			if [ "$?" != 0 ]; then
				echo "\"sysfilter_extract --syscalls-flat $prog\" failed"
			fi
			if [ -e "$FIXTURE_PATH/$filename.txt" ]; then
				diff=$(unbuffer git --no-pager diff --no-index -- "$FIXTURE_PATH/$filename".txt "$FIXTURE_PATH/$filename"_new.txt)
				if [ "$?" != 0 ]; then
					echo "\"sysfilter_extract --syscalls-flat $prog\" changed"
					echo "$diff"
				fi
			fi
			mv "$FIXTURE_PATH/$filename"{_new,}.txt
		fi
	fi
}

if [ "$1" != "" ]; then
	test_program "$1"
else
	mkdir -p "$FIXTURE_PATH"
	paths="/usr/bin/ /sbin/"
	if [ `readlink -f /bin` == "/bin" ]; then
		paths="$paths /bin"
	fi
	binaries=$(find $paths -executable -type f | grep -v callander)
	# note: this is the moreutils parallel instead of GNU parallel
	if [ -e /usr/bin/parallel-moreutils ]; then
		parallel-moreutils "$0" -- $binaries
	else
		parallel "$0" -- $binaries
	fi
fi
