#!/usr/bin/env python3

from panda import panda, blocking
from sys import argv

# No arguments, i386. Otherwise argument should be guest arch
generic_type = argv[1] if len(argv) > 1 else "i386"

panda = Panda(generic=generic_type) # You probably want to change this to not be a generic VM

@blocking
def run_osi():
    # First revert to root snapshot, then type a command via serial

    panda.revert_sync("root")
    # XXX: First we're updating sources.list to be up to date just for the provided qcows :(
    # Also pull down new keys that are expired
    payload = """sed -i 's/ftp/archive/g' /etc/apt/sources.list # Update sources.list for old wheezy VMs
    sed -i 's/http:\/\/security.debian.org\//http:\/\/archive.debian.org\/debian-security/g' /etc/apt/sources.list
    apt-key adv --keyserver keys.gnupg.net --recv-keys 473041FA B98321F9 46925553 65FFB764
    apt-get update
    hwclock -s # Update system clock from hardware clock (qemu should provide this by default)
    apt-get install -y --force-yes build-essential linux-headers-$(uname -r)* python subversion
    svn export --non-interactive https://github.com/panda-re/panda/trunk/panda/plugins/osi_linux/utils/kernelinfo
    cd kernelinfo && make; cd
    insmod kernelinfo/kernelinfo.ko"""

    # Run payload, get results
    for p in payload.split("\n"):
        r = panda.run_serial_cmd(p, no_timeout=True)

    print("Done with setup! Time to parse results")

    r = panda.run_serial_cmd("python kernelinfo/kernelinfo_parse.py", no_timeout=True)

    with open("osi_results.txt", "w") as f:
        f.write(r)

    panda.end_analysis()

panda.queue_async(run_osi)

panda.run()
