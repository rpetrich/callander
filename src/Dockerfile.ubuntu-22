FROM ubuntu:22.04
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y gdb binutils less moreutils expect git python3 ruby bc bzip2 curl gcc busybox file gettext bsdmainutils bind9-host systemd net-tools jq psmisc kmod landscape-common login lsb-release util-linux make debuginfod
ENV DEBUGINFOD_URLS="https://debuginfod.ubuntu.com"
