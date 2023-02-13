#!/bin/bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ -z "$1" ]; then
	echo "usage: $0 ubuntu_22.04" >&2
	exit 1
fi

for file in sysfilter_fixtures_$1/*.txt; do
	filename=${file#sysfilter_fixtures_$1/}
	"$SCRIPT_DIR/systranslate" < "sysfilter_fixtures_$1/$filename" 2> sysfilter.txt
	if [ -s sysfilter.txt ]; then
		egrep -o -e '\b[[:lower:]]+\(' -- "callander_fixtures_$1/$filename" | uniq | cut -d '(' -f 1 > callander.txt
		diff=$(unbuffer git --no-pager diff --no-index -- sysfilter.txt callander.txt)
		if [ "$?" != 0 ]; then
			echo "callander found differing syscalls between sysfilter_fixtures_$1/$filename and callander_fixtures_$1/$filename"
			echo "$diff" | tail +5
		fi
	else
		echo "sysfilter was unable to process sysfilter_fixtures_$1/$filename"
	fi
done
rm sysfilter.txt
rm callander.txt
