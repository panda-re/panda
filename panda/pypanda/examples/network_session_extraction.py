#!/usr/bin/env python3
from time import sleep
from sys import argv
from os import path, remove
from scapy.all import Ether, wrpcap
from panda import Panda, blocking, ffi

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

pcap_path = "out.pcap"

recording_name = "wget_google"
for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
    if path.isfile(f): remove(f)

# if recording doesn't exist, take one
@blocking
def take_recording():
    panda.record_cmd("wget google.com", recording_name=recording_name)
    panda.end_analysis()

if not path.isfile(recording_name+"-rr-snp"):
    print("Recording didn't exist. Creating...")
    panda.queue_async(take_recording)
    panda.run()

@panda.cb_virt_mem_after_read(procname="wget")
def virt_mem_after_read(cpustate, pc, addr, size, buf):
	curbuf = ffi.cast("char*", buf)
	current = panda.get_current_process(cpustate)
	if current != ffi.NULL:
		if size >= 5:
			buf_addr = hex(int(ffi.cast("uint64_t", buf)))
			buf_str = ffi.string(ffi.cast("char*",buf)).decode(errors='ignore')
			print("Read buf: %s, size: %x, at pc: %x %s" %(buf_addr[2:], size, addr, buf_str))
	return 0

packets = []
@panda.cb_replay_handle_packet(procname="wget")
def handle_packet(cpustate,buf,size,direction,old_buf_addr):
	buf_uint8 = ffi.cast("uint8_t*", buf)
	packets.append(Ether([buf_uint8[i] for i in range(size)]))
	return 0

panda.enable_memcb()
panda.run_replay(recording_name)
wrpcap(pcap_path, packets)

for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
    if path.isfile(f): remove(f)
