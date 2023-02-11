#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

source /etc/os-release
FIXTURE_PATH="$SCRIPT_DIR/callander_fixtures_"$ID"_"$VERSION_ID

case "$ID" in
	alpine)
		lib_path=/usr/lib
		ruby_version="3.1.3"
		python_minor_version="10"
		;;
	ubuntu)
		lib_path=/usr/lib/x86_64-linux-gnu
		if [ "$VERSION_ID" = "22.04" ]; then
			ruby_version="3.0.0"
			python_minor_version="10"
		else
			ruby_version="2.7.0"
			python_minor_version="8"
		fi
		;;
	fedora)
		lib_path=/lib64
		ruby_version="3.1.0"
		python_minor_version="8"
		;;
esac

declare -A program_args=(
	# perl
	["aclocal-1.16"]="--block-function Perl_pp_syscall"
	["aclocal"]="--block-function Perl_pp_syscall"
	["addgroup"]="--block-function Perl_pp_syscall"
	["adduser"]="--block-function Perl_pp_syscall"
	["apt-file"]="--block-function Perl_pp_syscall"
	["autoheader"]="--block-function Perl_pp_syscall"
	["autom4te"]="--block-function Perl_pp_syscall"
	["automake-1.16"]="--block-function Perl_pp_syscall"
	["automake"]="--block-function Perl_pp_syscall"
	["autoreconf"]="--block-function Perl_pp_syscall"
	["autoscan"]="--block-function Perl_pp_syscall"
	["autoupdate"]="--block-function Perl_pp_syscall"
	["c_rehash"]="--block-function Perl_pp_syscall"
	["callgrind_annotate"]="--block-function Perl_pp_syscall"
	["callgrind_control"]="--block-function Perl_pp_syscall"
	["cg_annotate"]="--block-function Perl_pp_syscall"
	["cg_diff"]="--block-function Perl_pp_syscall"
	["checkbandwidth"]="--block-debug-function Perl_pp_syscall"
	["chronic"]="--block-debug-function Perl_pp_syscall"
	["ckbcomp"]="--block-function Perl_pp_syscall"
	["combine"]="--block-debug-function Perl_pp_syscall"
	["compose"]="--block-function Perl_pp_syscall"
	["corelist"]="--block-function Perl_pp_syscall"
	["cpan"]="--block-function Perl_pp_syscall"
	["cpan5.30-x86_64-linux-gnu"]="--block-function Perl_pp_syscall"
	["cpan5.34-x86_64-linux-gnu"]="--block-function Perl_pp_syscall"
	["cpan5.36-x86_64-linux-gnu"]="--block-function Perl_pp_syscall"
	["deb-systemd-helper"]="--block-function Perl_pp_syscall"
	["deb-systemd-invoke"]="--block-function Perl_pp_syscall"
	["debconf-apt-progress"]="--block-function Perl_pp_syscall"
	["debconf-communicate"]="--block-function Perl_pp_syscall"
	["debconf-copydb"]="--block-function Perl_pp_syscall"
	["debconf-escape"]="--block-function Perl_pp_syscall"
	["debconf-set-selections"]="--block-function Perl_pp_syscall"
	["debconf-show"]="--block-function Perl_pp_syscall"
	["debconf"]="--block-function Perl_pp_syscall"
	["debugperl"]="--block-function Perl_pp_syscall"
	["delgroup"]="--block-function Perl_pp_syscall"
	["deluser"]="--block-function Perl_pp_syscall"
	["dh_autotools-dev_restoreconfig"]="--block-function Perl_pp_syscall"
	["dh_autotools-dev_updateconfig"]="--block-function Perl_pp_syscall"
	["dh_bash-completion"]="--block-function Perl_pp_syscall"
	["dpkg-architecture"]="--block-function Perl_pp_syscall"
	["dpkg-buildflags"]="--block-function Perl_pp_syscall"
	["dpkg-buildpackage"]="--block-function Perl_pp_syscall"
	["dpkg-checkbuilddeps"]="--block-function Perl_pp_syscall"
	["dpkg-distaddfile"]="--block-function Perl_pp_syscall"
	["dpkg-genbuildinfo"]="--block-function Perl_pp_syscall"
	["dpkg-genchanges"]="--block-function Perl_pp_syscall"
	["dpkg-gencontrol"]="--block-function Perl_pp_syscall"
	["dpkg-gensymbols"]="--block-function Perl_pp_syscall"
	["dpkg-mergechangelogs"]="--block-function Perl_pp_syscall"
	["dpkg-name"]="--block-function Perl_pp_syscall"
	["dpkg-parsechangelog"]="--block-function Perl_pp_syscall"
	["dpkg-preconfigure"]="--block-function Perl_pp_syscall"
	["dpkg-reconfigure"]="--block-function Perl_pp_syscall"
	["dpkg-scanpackages"]="--block-function Perl_pp_syscall"
	["dpkg-scansources"]="--block-function Perl_pp_syscall"
	["dpkg-shlibdeps"]="--block-function Perl_pp_syscall"
	["dpkg-source"]="--block-function Perl_pp_syscall"
	["dpkg-vendor"]="--block-function Perl_pp_syscall"
	["edit"]="--block-function Perl_pp_syscall"
	["enc2xs"]="--block-function Perl_pp_syscall"
	["encguess"]="--block-function Perl_pp_syscall"
	["find-dbgsym-packages"]="--block-function Perl_pp_syscall"
	["gen-preseed"]="--block-function Perl_pp_syscall"
	["grog"]="--block-function Perl_pp_syscall"
	["h2ph"]="--block-function Perl_pp_syscall"
	["h2xs"]="--block-function Perl_pp_syscall"
	["helpztags"]="--block-function Perl_pp_syscall"
	["ifnames"]="--block-function Perl_pp_syscall"
	["instmodsh"]="--block-function Perl_pp_syscall"
	["json_pp"]="--block-function Perl_pp_syscall"
	["keytab-lilo"]="--block-function Perl_pp_syscall"
	["libnetcfg"]="--block-function Perl_pp_syscall"
	["linux-check-removal"]="--block-function Perl_pp_syscall"
	["linux-update-symlinks"]="--block-function Perl_pp_syscall"
	["linux-version"]="--block-function Perl_pp_syscall"
	["luksformat"]="--block-function Perl_pp_syscall"
	["make-first-existing-target"]="--block-function Perl_pp_syscall"
	["md5pass"]="--block-function Perl_pp_syscall"
	["mkdiskimage"]="--block-function Perl_pp_syscall"
	["ms_print"]="--block-function Perl_pp_syscall"
	["mtrace"]="--block-function Perl_pp_syscall"
	["niceload"]="--block-function Perl_pp_syscall"
	["pam-auth-update"]="--block-function Perl_pp_syscall"
	["pam_getenv"]="--block-function Perl_pp_syscall"
	["parcat"]="--block-function Perl_pp_syscall"
	["parsort"]="--block-function Perl_pp_syscall"
	["perl"]="--block-function Perl_pp_syscall"
	["perl5.30.0"]="--block-function Perl_pp_syscall"
	["perl5.30-x86_64-linux-gnu"]="--block-function Perl_pp_syscall"
	["perl5.34.0"]="--block-function Perl_pp_syscall"
	["perl5.34-x86_64-linux-gnu"]="--block-function Perl_pp_syscall"
	["perl5.36.0"]="--block-function Perl_pp_syscall"
	["perl5.36-x86_64-linux-gnu"]="--block-function Perl_pp_syscall"
	["perlbug"]="--block-function Perl_pp_syscall"
	# ["perldoc"]="--block-function Perl_pp_syscall"
	["perlivp"]="--block-function Perl_pp_syscall"
	["perlthanks"]="--block-function Perl_pp_syscall"
	["piconv"]="--block-function Perl_pp_syscall"
	["pl2pm"]="--block-function Perl_pp_syscall"
	["pod2html"]="--block-function Perl_pp_syscall"
	["pod2man"]="--block-function Perl_pp_syscall"
	["pod2text"]="--block-function Perl_pp_syscall"
	["pod2usage"]="--block-function Perl_pp_syscall"
	["podchecker"]="--block-function Perl_pp_syscall"
	["podselect"]="--block-function Perl_pp_syscall"
	["popularity-contest"]="--block-function Perl_pp_syscall"
	["ppmtolss16"]="--block-function Perl_pp_syscall"
	["print"]="--block-function Perl_pp_syscall"
	["prove"]="--block-function Perl_pp_syscall"
	["ptar"]="--block-function Perl_pp_syscall"
	["ptardiff"]="--block-function Perl_pp_syscall"
	["ptargrep"]="--block-function Perl_pp_syscall"
	["pxelinux-options"]="--block-function Perl_pp_syscall"
	["regexp-assemble"]="--block-function Perl_pp_syscall"
	["rrsync"]="--block-function Perl_pp_syscall"
	["run-mailcap"]="--block-function Perl_pp_syscall"
	["see"]="--block-function Perl_pp_syscall"
	["shasum"]="--block-function Perl_pp_syscall"
	["sha1pass"]="--block-function Perl_pp_syscall"
	["snmpconf"]="--block-function Perl_pp_syscall"
	["splain"]="--block-function Perl_pp_syscall"
	["sql"]="--block-function Perl_pp_syscall"
	["streamzip"]="--block-function Perl_pp_syscall"
	["syslinux2ansi"]="--block-function Perl_pp_syscall"
	["tasksel"]="--block-function Perl_pp_syscall"
	["ts"]="--block-function Perl_pp_syscall"
	["ucfq"]="--block-function Perl_pp_syscall"
	["update-locale"]="--block-function Perl_pp_syscall"
	["update-mime"]="--block-function Perl_pp_syscall"
	["update-rc.d"]="--block-function Perl_pp_syscall"
	["validlocale"]="--block-function Perl_pp_syscall"
	["vidir"]="--block-function Perl_pp_syscall"
	["vipe"]="--block-function Perl_pp_syscall"
	["xsubpp"]="--block-function Perl_pp_syscall"
	["zipdetails"]="--block-function Perl_pp_syscall"
	["zrun"]="--block-function Perl_pp_syscall"
	["hmm-assembler.pl"]="--block-function Perl_pp_syscall"
	["zff2gff3.pl"]="--block-function Perl_pp_syscall"
	["patch-hmm.pl"]="--block-function Perl_pp_syscall"
	["xt_geoip_query"]="--block-function Perl_pp_syscall"
	# ruby
	["bundle2.7"]="--block-debug-function rb_f_syscall"
	["bundle3.0"]="--block-debug-function rb_f_syscall"
	["bundler2.7"]="--block-debug-function rb_f_syscall"
	["bundler3.0"]="--block-debug-function rb_f_syscall"
	["erb"]="--block-debug-function rb_f_syscall"
	["erb2.7"]="--block-debug-function rb_f_syscall"
	["erb3.0"]="--block-debug-function rb_f_syscall"
	# ["gem"]="--block-debug-function rb_f_syscall"
	["gem2.7"]="--block-debug-function rb_f_syscall"
	["gem3.0"]="--block-debug-function rb_f_syscall"
	["irb"]="--block-debug-function rb_f_syscall"
	["irb2.7"]="--block-debug-function rb_f_syscall"
	["irb3.0"]="--block-debug-function rb_f_syscall"
	["racc2.7"]="--block-debug-function rb_f_syscall"
	["racc2y2.7"]="--block-debug-function rb_f_syscall"
	["racc3.0"]="--block-debug-function rb_f_syscall"
	["rake"]="--block-debug-function rb_f_syscall"
	["rake3.0"]="--block-debug-function rb_f_syscall"
	["rbs3.0"]="--block-debug-function rb_f_syscall"
	["rdoc"]="--block-debug-function rb_f_syscall"
	["rdoc2.7"]="--block-debug-function rb_f_syscall"
	["rdoc3.0"]="--block-debug-function rb_f_syscall"
	["ri"]="--block-debug-function rb_f_syscall"
	["ri2.7"]="--block-debug-function rb_f_syscall"
	["ri3.0"]="--block-debug-function rb_f_syscall"
	# ["ruby"]="--block-debug-function rb_f_syscall --dlopen $lib_path/ruby/$ruby_version/enc/encdb.so --dlopen $lib_path/ruby/$ruby_version/enc/trans/transdb.so --dlopen $lib_path/ruby/$ruby_version/monitor.so"
	# ["ruby2.7"]="--block-debug-function rb_f_syscall --dlopen $lib_path/ruby/$ruby_version/enc/encdb.so --dlopen $lib_path/ruby/$ruby_version/enc/trans/transdb.so --dlopen $lib_path/ruby/$ruby_version/monitor.so"
	# ["ruby3.0"]="--block-debug-function rb_f_syscall --dlopen $lib_path/ruby/$ruby_version/enc/encdb.so --dlopen $lib_path/ruby/$ruby_version/enc/trans/transdb.so --dlopen $lib_path/ruby/$ruby_version/monitor.so"
	["typeprof3.0"]="--block-debug-function rb_f_syscall"
	["update_rubygems"]="--block-debug-function rb_f_syscall"
	["y2racc2.7"]="--block-debug-function rb_f_syscall"
	# both
	["ex"]="--block-function Perl_pp_syscall --block-debug-function rb_f_syscall"
	["rview"]="--block-function Perl_pp_syscall --block-debug-function rb_f_syscall"
	["rvim"]="--block-function Perl_pp_syscall --block-debug-function rb_f_syscall"
	["vi"]="--block-function Perl_pp_syscall --block-debug-function rb_f_syscall"
	["view"]="--block-function Perl_pp_syscall --block-debug-function rb_f_syscall"
	["vim"]="--block-function Perl_pp_syscall --block-debug-function rb_f_syscall"
	["vimdiff"]="--block-function Perl_pp_syscall --block-debug-function rb_f_syscall"
	["vim.nox"]="--block-function Perl_pp_syscall --block-debug-function rb_f_syscall"
	# nm
	# ["nm"]="--dlopen /usr/bin/../bin/../lib/bfd-plugins/liblto_plugin.so"
)

test_program () {
	local prog="$1"
	local filename="${prog##*/}"
	local flags="${program_args[$filename]} "
	filename="${prog##*/}"
	if [ -g "$prog" -o -u "$prog" ]; then
		rm -f "$FIXTURE_PATH/$filename.txt"
	else
		if [ "/sbin/$filename" = "$prog" -a -e "/bin/$filename" ]; then
			# skipping since duplicate binary in /sbin
			return
		else
			"$SCRIPT_DIR/callander" --skip-running --show-permitted --block-syscall execve --block-syscall execveat --ignore-dlopen $flags-- "$prog" 2> "$FIXTURE_PATH/$filename"_new.txt
			if [ "$?" != 0 ]; then
				echo "\"callander --skip-running --show-permitted --block-syscall execve --block-syscall execveat --ignore-dlopen $flags-- $prog\" failed"
			fi
			if [ -e "$FIXTURE_PATH/$filename.txt" ]; then
				diff=$(unbuffer git --no-pager diff --no-index -- "$FIXTURE_PATH/$filename".txt "$FIXTURE_PATH/$filename"_new.txt)
				if [ "$?" != 0 ]; then
					echo "\"callander --skip-running --show-permitted --block-syscall execve --block-syscall execveat --ignore-dlopen $flags-- $prog\" changed"
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
	local flags="${program_args[$prog_name]} "
	run_and_capture callander --block-syscall execve --block-syscall execveat --ignore-dlopen --stay-attached $flags-- "$@" > "/tmp/$prog_name-with-callander.txt"
	run_and_capture "$@" > "/tmp/$prog_name.txt"
	diff=$(unbuffer git --no-pager diff --no-index -- "/tmp/$prog_name.txt" "/tmp/$prog_name-with-callander.txt")
	if [ "$?" != 0 ]; then
		echo "\"callander --block-syscall execve --block-syscall execveat --ignore-dlopen --stay-attached $flags-- $@\" has differing output"
		echo "$diff"
	else
		echo "\"callander --block-syscall execve --block-syscall execveat --ignore-dlopen --stay-attached $flags-- $@\" has matching output"
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
	echo $(grep -R -e 'permitted syscalls' -- "$FIXTURE_PATH" | wc -l)/$(ls "$FIXTURE_PATH" | wc -l) binaries successfully processed
	echo failing tests:
	grep -R -e 'callander: ' -- "$FIXTURE_PATH" | grep -v 'permitted' | cut -d ':' -f 1 | uniq
fi
