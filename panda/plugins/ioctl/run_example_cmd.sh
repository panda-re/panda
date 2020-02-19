#! /bin/bash

wget -nc -q --show-progress http://panda-re.mit.edu/qcows/linux/ubuntu/1804/x86_64/bionic-server-cloudimg-amd64.qcow2
wget -nc -q --show-progress http://panda-re.mit.edu/qcows/linux/ubuntu/1804/x86_64/kernelinfo.conf

../../../build/x86_64-softmmu/panda-system-x86_64 \
    -m 1G \
    -loadvm root \
    -nographic \
    -os linux-64-ubuntu:4.15.0-72-generic \
    -panda osi \
    -panda osi_linux:kconf_file=./kernelinfo.conf,kconf_group=ubuntu:4.15.0-72-generic:64 \
    -panda syscalls2:profile=linux_x86_64 \
    -panda ioctl:out_log="ioctl.json" \
   ./bionic-server-cloudimg-amd64.qcow2