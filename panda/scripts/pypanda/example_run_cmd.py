#!/usr/bin/env python3

from pypanda import *
from sys import argv

from qcows import get_qcow, get_qcow_info

# No arguments, i386. Otherwise argument should be guest arch
qfile = argv[1] if len(argv) > 1 else None
q = get_qcow_info(qfile)
qf = get_qcow(qfile)
panda = Panda(qcow=qf, os=q.os, expect_prompt=q.prompt)


@alwaysasync
def run_it():
    guest_command = "/mnt/bin/jq . /mnt/inputs/fixed.json"
    copy_directory = "/tmp/jqB" # Host directory with file
    iso_name="test.iso"
    recording_name="recording"

    panda.run_cmd(guest_command, copy_directory, iso_name, recording_name)

    print("Finished recording")

@alwaysasync
def quit():
    print("Finished with run_it, let's quit")
    panda.run_monitor_cmd("quit")

panda.queue_async(run_it)
panda.queue_async(quit)

panda.run()
