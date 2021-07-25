#!/usr/bin/env python3
'''
network_session_extract.py

This example takes a recording of a network transaction. It then replays it and
sets a callback on packets sent out. It takes the data from example and uses
scapy to write the packets to a PCAP for further examination.

Run with: python3 network_session_extract.py
'''
from sys import argv
from os import path, remove
from scapy.all import Ether, wrpcap
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

pcap_path = "out.pcap"

recording_name = "wget_google"
for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
    if path.isfile(f): remove(f)


if not path.isfile(recording_name+"-rr-snp"):
	# if recording doesn't exist, take one
	@panda.queue_blocking
	def take_recording():
		panda.record_cmd("wget google.com", recording_name=recording_name)
		panda.end_analysis()
		print("Recording didn't exist. Creating...")
	panda.run()

packets = []
@panda.cb_replay_handle_packet(procname="wget")
def handle_packet(cpustate,buf,size,direction,old_buf_addr):
	buf_uint8 = panda.ffi.cast("uint8_t*", buf)
	packets.append(Ether([buf_uint8[i] for i in range(size)]))

panda.run_replay(recording_name)
wrpcap(pcap_path, packets)

for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
    if path.isfile(f): remove(f)
