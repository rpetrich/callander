#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ -z "$full_image" ]; then
	export full_image="$image-$(uname -m)"
fi
FIXTURE_PATH="callander_fixtures/$full_image"
if [ "$SCRIPT_DIR" != "$PWD" ]; then
	FIXTURE_PATH="$SCRIPT_DIR/$FIXTURE_PATH"
fi

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
			"$SCRIPT_DIR/callander_$arch" --skip-running --show-permitted --block-exec --ignore-dlopen -- "$prog" 2> "$FIXTURE_PATH/$filename"_new.txt
			if [ "$?" != 0 ]; then
				echo "\"callander --skip-running --show-permitted --block-exec --ignore-dlopen -- $prog\" failed"
			fi
			if [ -e "$FIXTURE_PATH/$filename.txt" ]; then
				diff=$(unbuffer git --no-pager diff --no-index -- "$FIXTURE_PATH/$filename".txt "$FIXTURE_PATH/$filename"_new.txt)
				if [ "$?" != 0 ]; then
					echo "\"callander --skip-running --show-permitted --block-exec --ignore-dlopen -- $prog\" changed"
					echo "$diff"
				fi
			fi
			mv "$FIXTURE_PATH/$filename"{_new,}.txt
		fi
	fi
}

run_and_capture () {
	"$@" 2>&1
	echo "exited with $?"
}

run_and_diff () {
	local prog_name=$(basename "$1")
	run_and_capture "$SCRIPT_DIR/callander" --block-exec --ignore-dlopen --stay-attached -- "$@" > "/tmp/$prog_name-with-callander.txt"
	run_and_capture "$@" > "/tmp/$prog_name.txt"
	diff=$(unbuffer git --no-pager diff --no-index -- "/tmp/$prog_name.txt" "/tmp/$prog_name-with-callander.txt")
	if [ "$?" != 0 ]; then
		echo "\"callander --block-exec --ignore-dlopen --stay-attached -- $@\" has differing output"
		echo "$diff"
	else
		echo "\"callander --block-exec --ignore-dlopen --stay-attached -- $@\" has matching output"
	fi
	rm -f "/tmp/$prog_name-with-callander.txt" "/tmp/$prog_name.txt"
}

if [ "$1" != "" ]; then
	test_program "$1"
else
	# if [ $ID == ubuntu ]; then
	# 	run_and_diff echo "hello world"
	# 	run_and_diff bash -c "echo hi"
	# 	run_and_diff ls -lah
	# 	run_and_diff apt --version
	# 	run_and_diff python3 --version
	# 	run_and_diff ruby --version
	# 	run_and_diff stat .
	# 	run_and_diff ar --version
	# 	run_and_diff base64 "$0"
	# 	run_and_diff basename /hello/world
	# 	run_and_diff bc --version
	# 	run_and_diff busybox sh -c 'echo hi'
	# 	run_and_diff bzip2 --version
	# 	run_and_diff gcc --version
	# 	run_and_diff cat "$0"
	# 	run_and_diff c++filt _ZSt18uncaught_exceptionv
	# 	run_and_diff containerd --version
	# 	run_and_diff curl localhost
	# 	run_and_diff curl --version
	# 	run_and_diff dash -c 'echo hi'
	# 	run_and_diff date -I
	# 	run_and_diff diff --version
	# 	run_and_diff df -h /
	# 	run_and_diff docker --version
	# 	run_and_diff hostname
	# 	run_and_diff dpkg-query --status
	# 	run_and_diff du -h "$0"
	# 	run_and_diff env -u _ -u LD_PRELOAD -u LD_BIND_NOW
	# 	run_and_diff false
	# 	run_and_diff fincore `which false`
	# 	run_and_diff file /bin/file
	# 	run_and_diff getent hosts localhost
	# 	run_and_diff getopt h -s hi
	# 	run_and_diff gettext hi
	# 	run_and_diff git --version
	# 	run_and_diff gpasswd --help
	# 	run_and_diff grep -e hi "$0"
	# 	run_and_diff gzip --version
	# 	run_and_diff hd `which callander`
	# 	run_and_diff head 10 "$0"
	# 	run_and_diff host localhost
	# 	run_and_diff hostid
	# 	run_and_diff hostname
	# 	run_and_diff hostnamectl status
	# 	run_and_diff iconv -l
	# 	run_and_diff id
	# 	run_and_diff ifconfig
	# 	run_and_diff ipcs
	# 	run_and_diff ipmaddr
	# 	run_and_diff join "$0" "$0"
	# 	run_and_diff journalctl --list-boots
	# 	run_and_diff jq --version
	# 	run_and_diff killall -l
	# 	run_and_diff kmod list
	# 	run_and_diff kmod static-nodes
	# 	run_and_diff landscape-sysinfo --sysinfo-plugins=Disk,Network
	# 	run_and_diff last
	# 	run_and_diff lastlog
	# 	run_and_diff ld --version
	# 	run_and_diff locale
	# 	run_and_diff loginctl --no-pager
	# 	run_and_diff logname
	# 	run_and_diff look hell
	# 	run_and_diff lsb_release -a
	# 	run_and_diff lsblk
	# 	run_and_diff lscpu
	# 	run_and_diff lshw
	# 	run_and_diff lsipc
	# 	run_and_diff lslocks
	# 	run_and_diff lslogins -o=UID,USER,GID,GROUP,LAST-LOGIN
	# 	run_and_diff lsmem
	# 	run_and_diff lsmod
	# 	run_and_diff lsmod
	# 	run_and_diff lspci
	# 	run_and_diff m4 --help
	# 	run_and_diff make --version
	# 	run_and_diff manpath
	# 	run_and_diff md5sum "$0"
	# 	run_and_diff mesg
	# 	run_and_diff mkdir -p .
	# 	run_and_diff modprobe -c
	# 	run_and_diff namei "$0"
	# 	run_and_diff nc
	# 	run_and_diff ncal
	# 	run_and_diff netplan get all
	# 	run_and_diff networkctl -a --no-pager
	# 	run_and_diff nl "$0"
	# 	run_and_diff nm /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
	# 	run_and_diff node -e 'console.log("hi")'
	# 	run_and_diff nohup --version
	# 	run_and_diff nologin
	# 	run_and_diff nproc
	# 	run_and_diff nslookup localhost
	# 	run_and_diff objdump --all-headers `which callander`
	# 	run_and_diff od "$0"
	# 	run_and_diff openssl sha512 "$0"
	# 	run_and_diff paste "$0" "$0"
	# 	run_and_diff perl -e 'print "hi"'
	# 	run_and_diff pinky
	# 	run_and_diff printf 'hello world'
	# 	run_and_diff prlimit
	# 	run_and_diff python3 -c 'print("hi")'
	# 	run_and_diff readelf -S `which callander`
	# 	run_and_diff readlink -f .
	# 	run_and_diff realpath .
	# 	run_and_diff resolvectl
	# 	run_and_diff rev "$0"
	# 	run_and_diff route
	# 	run_and_diff ruby -e 'print("hi")'
	# 	run_and_diff runc --version
	# 	run_and_diff sleep 1
	# 	run_and_diff snap list
	# 	run_and_diff sort "$0"
	# 	run_and_diff stat -f "$0"
	# 	run_and_diff static-sh -c 'printf hi'
	# 	run_and_diff strings `which callander`
	# 	run_and_diff systemctl list-units
	# 	run_and_diff tail -n 1 "$0"
	# 	run_and_diff test -e "$0"
	# 	run_and_diff tree "$SCRIPT_DIR"
	# 	run_and_diff true
	# 	run_and_diff uname -a
	# 	run_and_diff uniq "$0"
	# 	run_and_diff uptime --pretty
	# 	run_and_diff users
	# 	# run_and_diff wasmtime --version
	# 	run_and_diff wc "$0"
	# 	run_and_diff which echo
	# 	run_and_diff whoami
	# fi

	# exit 0
	echo Testing $full_image:
	mkdir -p "$FIXTURE_PATH"
	paths="/usr/bin/ /sbin/"
	if [ `readlink -f /bin` == "/bin" ]; then
		paths="$paths /bin"
	fi
	binaries=$(find $paths -executable -type f | grep -v callander)
	# note: this is the moreutils parallel instead of GNU parallel
	if command -v parallel-moreutils >/dev/null; then
		parallel-moreutils "$0" -- $binaries
	else
		if command -v parallel >/dev/null; then
			parallel "$0" -- $binaries
		else
			for b in $binaries; do
				test_program "$b"
			done
		fi
	fi
	echo $(grep -R -e 'permitted syscalls' -- "$FIXTURE_PATH" | wc -l)/$(ls "$FIXTURE_PATH" | wc -l) binaries successfully processed
	echo failing tests:
	grep -R -e 'callander: ' -- "$FIXTURE_PATH" | grep -v 'permitted' | cut -d ':' -f 1 | uniq
fi
