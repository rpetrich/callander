#!/bin/bash
source /etc/os-release
echo "export PS1='$image:\\w\\$ '" > ~/.bashrc
exec bash -i
