#!/usr/bin/env python3
'''
example_network.py

This example implements the networks same functionality as the network plugin in
panda. It registers replay_handle_packet callback, converts the buffer, and
writes the buffer out to a pcap.

Run with: python3 example_network.py i386 out.pcap /path/to/recording
'''
from pypanda import *
from time import sleep
from sys import argv
from scapy.all import Ether, wrpcap
import qcows

# Single arg of arch, defaults to i386
arg1 = "i386" if len(argv) <= 1 else argv[1]

q = qcows.get_qcow(arg1)
panda = Panda(qcow=q)

out_file = argv[2]
recording = argv[3]

@panda.callback.init
def init(handle):
	panda.register_callback(handle, panda.callback.replay_handle_packet, \
							handle_packet)
	return True

packets = [] # keep all the packets
@panda.callback.replay_handle_packet
def handle_packet(cpustate,buf,size,direction,old_buf_addr):
	packets.append(Ether("".join([chr(buf[i]) for i in range(size)])))
	return 0

panda.load_python_plugin(init,"example_network")
panda.begin_replay(recording)
panda.run()
wrpcap(out_file,packets) # write output to pcap
